import os
import shutil
import subprocess
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = bytes(range(256)) * 50 + b"tail"  # 12804 байт: несколько 8 КБ-кусков чтения
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def run_dgst(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "src.cli_parser", "dgst", *args],
        cwd=PROJECT_ROOT, capture_output=True, input=stdin,
    )


def system_hash(algorithm, path):
    """Хеш системной утилитой (TEST-3) или None, если подходящей утилиты нет."""
    commands = {
        "sha256": [["sha256sum", path], ["shasum", "-a", "256", path]],
        "sha3-256": [["sha3sum", "-a", "256", path], ["openssl", "dgst", "-sha3-256", "-r", path]],
        "blake3": [["b3sum", path]],
    }[algorithm]
    for cmd in commands:
        if shutil.which(cmd[0]):
            out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
            return out.split()[0]
    if algorithm == "blake3":
        try:
            import blake3  # эталонная реализация, если установлена
        except ImportError:
            return None
        with open(path, "rb") as f:
            return blake3.blake3(f.read()).hexdigest()
    return None


class DgstTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.file = self.path("data.bin")
        with open(self.file, "wb") as f:
            f.write(DATA)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def path(self, name):
        return os.path.join(self.tmp, name)


class TestDgstOutput(DgstTestBase):
    def test_sum_format(self):  # CLI-4
        r = run_dgst("--algorithm", "sha256", "--input", self.file)
        self.assertEqual(r.returncode, 0, r.stderr)
        digest = system_hash("sha256", self.file)
        self.assertEqual(r.stdout.decode(), f"{digest}  {self.file}\n")
        self.assertEqual(r.stderr, b"")

    def test_matches_system_tools(self):  # TEST-3
        for algorithm in ("sha256", "sha3-256", "blake3"):
            with self.subTest(algorithm=algorithm):
                expected = system_hash(algorithm, self.file)
                if expected is None:
                    self.skipTest(f"нет эталонной утилиты для {algorithm}")
                r = run_dgst("--algorithm", algorithm, "--input", self.file)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.decode().split("  ")[0], expected)

    @unittest.skipIf(shutil.which("shasum") is None and shutil.which("sha256sum") is None,
                     "нет sha256sum/shasum")
    def test_byte_identical_to_sha256sum(self):  # TEST-3: diff без различий
        tool = ["sha256sum"] if shutil.which("sha256sum") else ["shasum", "-a", "256"]
        sys_out = subprocess.run([*tool, "data.bin"], cwd=self.tmp, capture_output=True).stdout
        mine = subprocess.run(
            [sys.executable, "-m", "src.cli_parser", "dgst", "--algorithm", "sha256", "--input", "data.bin"],
            cwd=self.tmp, capture_output=True, env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
        ).stdout
        self.assertEqual(mine, sys_out)

    def test_empty_file(self):  # TEST-2
        empty = self.path("empty")
        open(empty, "wb").close()
        r = run_dgst("--algorithm", "sha256", "--input", empty)
        self.assertEqual(r.stdout.decode(), f"{EMPTY_SHA256}  {empty}\n")

    def test_stdin(self):
        r = run_dgst("--algorithm", "sha256", "--input", "-", stdin=b"abc")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), f"{ABC_SHA256}  -\n")

    def test_spec_examples_via_stdin(self):  # примеры тестовых команд из ТЗ (TEST-1)
        cases = [
            ("sha256", b"abc", ABC_SHA256),
            ("sha256", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            ("sha3-256", b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            ("sha3-256", b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            ("blake3", b"", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
        ]
        for algorithm, data, expected in cases:
            with self.subTest(algorithm=algorithm, data=data):
                r = run_dgst("--algorithm", algorithm, "--input", "-", stdin=data)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.decode(), f"{expected}  -\n")

    def test_empty_file_all_algorithms(self):  # TEST-2
        empty = self.path("empty")
        open(empty, "wb").close()
        for algorithm in ("sha256", "sha3-256", "blake3"):
            with self.subTest(algorithm=algorithm):
                expected = system_hash(algorithm, empty)
                if expected is None:
                    self.skipTest(f"нет эталонной утилиты для {algorithm}")
                r = run_dgst("--algorithm", algorithm, "--input", empty)
                self.assertEqual(r.stdout.decode(), f"{expected}  {empty}\n")

    def test_help_does_not_mention_encryption_options(self):  # CLI-3
        r = run_dgst("--help")
        self.assertEqual(r.returncode, 0)
        help_text = r.stdout.decode()
        for option in ("--algorithm", "--input", "--output", "--hmac", "--key", "--verify"):
            self.assertIn(option, help_text)
        # --key теперь есть у dgst (спринт 5, ключ MAC), остальные аргументы шифрования — нет
        for option in ("--iv", "--mode", "--encrypt", "--decrypt"):
            self.assertNotIn(option, help_text)

    def test_backslash_in_name_is_escaped(self):  # как в coreutils
        name = self.path("a\\b.txt")
        with open(name, "wb") as f:
            f.write(b"abc")
        r = run_dgst("--algorithm", "sha256", "--input", name)
        self.assertEqual(r.stdout.decode(), "\\" + ABC_SHA256 + "  " + name.replace("\\", "\\\\") + "\n")


class TestDgstOutputFile(DgstTestBase):  # CLI-5, IO-3
    def test_output_file_same_format_as_stdout(self):
        for algorithm in ("sha256", "sha3-256", "blake3"):
            with self.subTest(algorithm=algorithm):
                out = self.path(f"hash.{algorithm}")
                r_file = run_dgst("--algorithm", algorithm, "--input", self.file, "--output", out)
                r_std = run_dgst("--algorithm", algorithm, "--input", self.file)
                self.assertEqual(r_file.returncode, 0, r_file.stderr)
                self.assertEqual(r_file.stdout, b"")  # вместо stdout, а не вместе с ним
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), r_std.stdout)

    def test_stdout_bytes_do_not_depend_on_terminal_encoding(self):  # IO-3
        name = self.path("файл.txt")
        with open(name, "wb") as f:
            f.write(b"abc")
        out = self.path("hash.txt")
        r_std = subprocess.run(
            [sys.executable, "-m", "src.cli_parser", "dgst", "--algorithm", "sha256", "--input", name],
            cwd=PROJECT_ROOT, capture_output=True, env={**os.environ, "PYTHONIOENCODING": "latin-1"},
        )
        self.assertEqual(r_std.returncode, 0, r_std.stderr)
        run_dgst("--algorithm", "sha256", "--input", name, "--output", out).check_returncode()
        with open(out, "rb") as f:
            self.assertEqual(f.read(), r_std.stdout)
        self.assertEqual(r_std.stdout, f"{ABC_SHA256}  {name}\n".encode())

    def test_stdin_to_output_file(self):
        out = self.path("hash.txt")
        run_dgst("--algorithm", "sha256", "--input", "-", "--output", out, stdin=b"abc").check_returncode()
        with open(out, "rb") as f:
            self.assertEqual(f.read(), f"{ABC_SHA256}  -\n".encode())

    def test_output_same_as_input_rejected(self):
        os.symlink(self.file, self.path("link"))
        for out in (self.file, self.path("link")):
            with self.subTest(output=out):
                r = run_dgst("--algorithm", "sha256", "--input", self.file, "--output", out)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("совпадает с --input", r.stderr.decode())
                with open(self.file, "rb") as f:
                    self.assertEqual(f.read(), DATA)  # входной файл не тронут

    def test_empty_paths_rejected(self):
        r = run_dgst("--algorithm", "sha256", "--input", self.file, "--output", "")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, b"")  # хеш не должен молча уйти в stdout
        self.assertNotEqual(run_dgst("--algorithm", "sha256", "--input", "").returncode, 0)

    def test_output_write_errors(self):  # IO-4
        r = run_dgst("--algorithm", "sha256", "--input", self.file, "--output", self.path("no/dir/h.txt"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("не существует", r.stderr.decode())
        r = run_dgst("--algorithm", "sha256", "--input", self.file, "--output", self.tmp)
        self.assertEqual(r.returncode, 1)
        self.assertIn("каталог", r.stderr.decode())

    def test_output_not_created_on_missing_input(self):
        out = self.path("hash.txt")
        r = run_dgst("--algorithm", "sha256", "--input", self.path("nope"), "--output", out)
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(out))


class TestDgstArguments(DgstTestBase):
    def test_encryption_arguments_rejected(self):  # CLI-3
        cases = [
            ("--key", "00112233445566778899aabbccddeeff"),
            ("--iv", "00112233445566778899aabbccddeeff"),
            ("--mode", "cbc"),
            ("--encrypt",),
            ("--decrypt",),
            ("--key=00112233445566778899aabbccddeeff",),
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                r = run_dgst("--algorithm", "sha256", "--input", self.file, *extra)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(extra[0].split("=")[0], r.stderr.decode())
                self.assertEqual(r.stdout, b"")

    def test_unknown_algorithm(self):
        for algorithm in ("aes", "md5", "sha3", "SHA256"):
            with self.subTest(algorithm=algorithm):
                r = run_dgst("--algorithm", algorithm, "--input", self.file)
                self.assertNotEqual(r.returncode, 0)

    def test_required_arguments(self):
        self.assertNotEqual(run_dgst("--algorithm", "sha256").returncode, 0)
        self.assertNotEqual(run_dgst("--input", self.file).returncode, 0)

    def test_abbreviations_and_duplicates_rejected(self):
        r = run_dgst("--alg", "sha256", "--input", self.file)
        self.assertNotEqual(r.returncode, 0)
        r = run_dgst("--algorithm", "sha256", "--algorithm", "blake3", "--input", self.file)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("несколько раз", r.stderr.decode())

    def test_file_errors(self):  # IO-4
        r = run_dgst("--algorithm", "sha256", "--input", self.path("nope"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("не найден", r.stderr.decode())
        r = run_dgst("--algorithm", "sha256", "--input", self.tmp)
        self.assertEqual(r.returncode, 1)
        self.assertIn("каталог", r.stderr.decode())


class TestChunkedReading(DgstTestBase):  # IO-1, IO-2
    def test_reads_in_bounded_chunks(self):
        from src.file_io import CHUNK_SIZE, iter_input_chunks
        chunks = list(iter_input_chunks(self.file))
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= CHUNK_SIZE for c in chunks))
        self.assertEqual(b"".join(chunks), DATA)


@unittest.skipUnless(os.environ.get("CRYPTOCORE_LARGE_TEST"), "задайте CRYPTOCORE_LARGE_TEST=1 (долго)")
class TestLargeFile(DgstTestBase):  # TEST-4
    def test_larger_than_1gb(self):
        big = self.path("big.bin")
        block = os.urandom(1 << 20)
        with open(big, "wb") as f:
            for _ in range(1025):  # 1 ГБ + 1 МБ
                f.write(block)
        r = run_dgst("--algorithm", "sha256", "--input", big)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode().split("  ")[0], system_hash("sha256", big))


if __name__ == "__main__":
    unittest.main()
