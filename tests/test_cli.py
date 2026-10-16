import os
import shutil
import subprocess
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "000102030405060708090a0b0c0d0e0f"
IV = "aabbccddeeff00112233445566778899"
NEW_MODES = ["cbc", "cfb", "ofb", "ctr"]
PLAINTEXT = b"CryptoCore sprint 2: CBC/CFB/OFB/CTR test file.\n\x00\x01\x02\xff" * 3  # не кратно 16


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.cli_parser", "--algorithm", "aes", *args],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )


def run_openssl(*args):
    return subprocess.run(["openssl", "enc", *args], capture_output=True, text=True)


class CLITestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.plain = self.path("plain.bin")
        with open(self.plain, "wb") as f:
            f.write(PLAINTEXT)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def read(self, name):
        with open(self.path(name), "rb") as f:
            return f.read()


class TestCLI(CLITestBase):
    def test_round_trip_with_iv_from_file(self):  # TEST-1
        for mode in NEW_MODES:
            with self.subTest(mode=mode):
                r = run_cli("--mode", mode, "--encrypt", "--key", KEY,
                            "--input", self.plain, "--output", self.path("c.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                r = run_cli("--mode", mode, "--decrypt", "--key", KEY,
                            "--input", self.path("c.bin"), "--output", self.path("d.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read("d.bin"), PLAINTEXT)

    def test_round_trip_with_explicit_iv(self):
        for mode in NEW_MODES:
            with self.subTest(mode=mode):
                run_cli("--mode", mode, "--encrypt", "--key", KEY,
                        "--input", self.plain, "--output", self.path("c.bin"))
                data = self.read("c.bin")
                with open(self.path("body.bin"), "wb") as f:
                    f.write(data[16:])
                r = run_cli("--mode", mode, "--decrypt", "--key", KEY, "--iv", data[:16].hex(),
                            "--input", self.path("body.bin"), "--output", self.path("d.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read("d.bin"), PLAINTEXT)

    def test_output_starts_with_random_iv(self):  # IV-1, IV-2
        run_cli("--mode", "ctr", "--encrypt", "--key", KEY, "--input", self.plain, "--output", self.path("c1.bin"))
        run_cli("--mode", "ctr", "--encrypt", "--key", KEY, "--input", self.plain, "--output", self.path("c2.bin"))
        c1, c2 = self.read("c1.bin"), self.read("c2.bin")
        self.assertEqual(len(c1), 16 + len(PLAINTEXT))
        self.assertNotEqual(c1[:16], c2[:16])

    def test_iv_rejected_on_encrypt(self):  # CLI-2, CLI-3
        r = run_cli("--mode", "cbc", "--encrypt", "--key", KEY, "--iv", IV,
                    "--input", self.plain, "--output", self.path("c.bin"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--iv", r.stderr)
        self.assertFalse(os.path.exists(self.path("c.bin")))

    def test_invalid_iv(self):
        for bad in ("zz" * 16, "aabb"):
            with self.subTest(iv=bad):
                r = run_cli("--mode", "cbc", "--decrypt", "--key", KEY, "--iv", bad,
                            "--input", self.plain, "--output", self.path("d.bin"))
                self.assertEqual(r.returncode, 1)
                self.assertIn("IV", r.stderr)

    def test_input_shorter_than_iv(self):  # IO-3
        with open(self.path("short.bin"), "wb") as f:
            f.write(b"123")
        r = run_cli("--mode", "ofb", "--decrypt", "--key", KEY,
                    "--input", self.path("short.bin"), "--output", self.path("d.bin"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("слишком короткий", r.stderr)

    def test_iv_rejected_for_ecb(self):  # ECB не использует IV
        r = run_cli("--mode", "ecb", "--decrypt", "--key", KEY, "--iv", IV,
                    "--input", self.plain, "--output", self.path("d.bin"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ECB", r.stderr)
        self.assertFalse(os.path.exists(self.path("d.bin")))

    def test_abbreviated_options_rejected(self):  # CLI-4 спринта 1: только точные имена аргументов
        r = run_cli("--mode", "cbc", "--enc", "--key", KEY, "--input", self.plain, "--output", self.path("c.bin"))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.path("c.bin")))

    def test_duplicate_options_rejected(self):  # CLI-4 спринта 1: конфликтующие аргументы
        r = run_cli("--mode", "cbc", "--encrypt", "--key", KEY, "--key", "2b7e151628aed2a6abf7158809cf4f3c",
                    "--input", self.plain, "--output", self.path("c.bin"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--key", r.stderr)
        self.assertFalse(os.path.exists(self.path("c.bin")))

    def test_hash_algorithm_rejected_for_encryption(self):
        r = subprocess.run([sys.executable, "-m", "src.cli_parser", "--algorithm", "sha256", "--mode", "cbc",
                            "--encrypt", "--input", self.plain], cwd=PROJECT_ROOT, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)

    def test_input_is_directory(self):  # IO-3 спринта 1: понятная ошибка вместо traceback
        r = run_cli("--mode", "cbc", "--encrypt", "--key", KEY, "--input", self.tmp, "--output", self.path("c.bin"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("каталог", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_output_same_as_input_rejected(self):  # исходный файл не должен затираться
        r = run_cli("--mode", "ctr", "--encrypt", "--key", KEY, "--input", self.plain, "--output", self.plain)
        self.assertNotEqual(r.returncode, 0)
        with open(self.plain, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_empty_output_rejected(self):  # раньше молча подставлялось имя по умолчанию
        r = run_cli("--mode", "ctr", "--encrypt", "--key", KEY, "--input", self.plain, "--output", "")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.plain + ".enc"))

    def test_ecb_still_works(self):  # STR-1 / CRY-1: регрессия спринта 1
        run_cli("--mode", "ecb", "--encrypt", "--key", KEY, "--input", self.plain, "--output", self.path("c.bin"))
        r = run_cli("--mode", "ecb", "--decrypt", "--key", KEY, "--input", self.path("c.bin"), "--output", self.path("d.bin"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("d.bin"), PLAINTEXT)
        self.assertEqual(len(self.read("c.bin")) % 16, 0)


class TestKeyGeneration(CLITestBase):
    def generated_key(self, stdout):
        lines = [l for l in stdout.splitlines() if l.startswith("[INFO] Generated random key: ")]
        self.assertEqual(len(lines), 1, stdout)  # KEY-2: ровно один раз
        key = lines[0].split(": ", 1)[1]
        self.assertEqual(len(bytes.fromhex(key)), 16)  # KEY-1
        return key

    def test_encrypt_without_key_then_decrypt(self):  # TEST-1
        for mode in ["ecb", *NEW_MODES]:
            with self.subTest(mode=mode):
                r = run_cli("--mode", mode, "--encrypt", "--input", self.plain, "--output", self.path("c.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                key = self.generated_key(r.stdout)
                # KEY-3: ключ не попадает в файл с шифртекстом
                self.assertNotIn(bytes.fromhex(key), self.read("c.bin"))
                r = run_cli("--mode", mode, "--decrypt", "--key", key,
                            "--input", self.path("c.bin"), "--output", self.path("d.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read("d.bin"), PLAINTEXT)

    def test_generated_keys_differ(self):
        keys = set()
        for _ in range(3):
            r = run_cli("--mode", "ctr", "--encrypt", "--input", self.plain, "--output", self.path("c.bin"))
            keys.add(self.generated_key(r.stdout))
        self.assertEqual(len(keys), 3)

    def test_decrypt_without_key_fails(self):  # CLI-4
        r = run_cli("--mode", "cbc", "--decrypt", "--input", self.plain, "--output", self.path("d.bin"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--key", r.stderr)
        self.assertFalse(os.path.exists(self.path("d.bin")))

    def test_weak_key_warning(self):  # CLI-5
        r = run_cli("--mode", "ctr", "--encrypt", "--key", "00" * 16,
                    "--input", self.plain, "--output", self.path("c.bin"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARNING]", r.stderr)
        self.assertNotIn("Generated random key", r.stdout)  # CLI-2: переданный ключ используется как есть

    def test_strong_key_no_warning(self):
        r = run_cli("--mode", "ctr", "--encrypt", "--key", "2b7e151628aed2a6abf7158809cf4f3c",
                    "--input", self.plain, "--output", self.path("c.bin"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("[WARNING]", r.stderr)


@unittest.skipIf(shutil.which("openssl") is None, "openssl не установлен")
class TestOpenSSLCompatibility(CLITestBase):
    def test_cryptocore_to_openssl(self):  # TEST-2
        for mode in NEW_MODES:
            with self.subTest(mode=mode):
                r = run_cli("--mode", mode, "--encrypt", "--key", KEY,
                            "--input", self.plain, "--output", self.path("c.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                data = self.read("c.bin")
                with open(self.path("body.bin"), "wb") as f:
                    f.write(data[16:])
                r = run_openssl(f"-aes-128-{mode}", "-d", "-K", KEY, "-iv", data[:16].hex(),
                                "-in", self.path("body.bin"), "-out", self.path("d.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read("d.bin"), PLAINTEXT)

    def test_openssl_to_cryptocore(self):  # TEST-3
        for mode in NEW_MODES:
            with self.subTest(mode=mode):
                r = run_openssl(f"-aes-128-{mode}", "-K", KEY, "-iv", IV,
                                "-in", self.plain, "-out", self.path("c.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                r = run_cli("--mode", mode, "--decrypt", "--key", KEY, "--iv", IV,
                            "--input", self.path("c.bin"), "--output", self.path("d.bin"))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read("d.bin"), PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
