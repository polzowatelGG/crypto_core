import os
import unittest
from unittest import mock
from src.csprng import CSPRNGError, generate_random_bytes
from src.cli_parser import weak_key_reason


class TestGenerateRandomBytes(unittest.TestCase):
    def test_length(self):
        for n in (0, 1, 16, 1000):
            with self.subTest(n=n):
                self.assertEqual(len(generate_random_bytes(n)), n)

    def test_key_uniqueness(self):  # TEST-2
        keys = set()
        for _ in range(1000):
            key = generate_random_bytes(16).hex()
            self.assertNotIn(key, keys, f"Найден дубликат ключа: {key}")
            keys.add(key)
        self.assertEqual(len(keys), 1000)

    def test_hamming_weight(self):  # TEST-4
        # 1000 ключей * 128 бит = 128000 бит; у честного генератора доля единиц ~0.5,
        # стандартное отклонение ~0.0014, так что границы 0.49..0.51 — это ~7 сигм
        keys = [generate_random_bytes(16) for _ in range(1000)]
        ones = sum(bin(b).count("1") for key in keys for b in key)
        ratio = ones / (len(keys) * 128)
        self.assertGreater(ratio, 0.49)
        self.assertLess(ratio, 0.51)

    def test_byte_distribution(self):
        # все 256 значений байта должны встречаться примерно одинаково часто
        data = generate_random_bytes(256 * 1000)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        # хи-квадрат с 255 степенями свободы: критическое значение для p=0.0001 ≈ 347
        expected = len(data) / 256
        chi2 = sum((c - expected) ** 2 / expected for c in counts)
        self.assertLess(chi2, 347)

    def test_invalid_arguments(self):
        with self.assertRaises(ValueError):
            generate_random_bytes(-1)
        for bad in (16.0, "16", None, True):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                generate_random_bytes(bad)

    def test_os_failure_is_reported(self):  # RNG-6
        for exc in (OSError("getrandom failed"), NotImplementedError("no entropy source")):
            with self.subTest(exc=exc), mock.patch("src.csprng.os.urandom", side_effect=exc):
                with self.assertRaises(CSPRNGError) as ctx:
                    generate_random_bytes(16)
                self.assertIn("источник случайности недоступен", str(ctx.exception))

    def test_short_read_is_reported(self):
        with mock.patch("src.csprng.os.urandom", return_value=b"\x00" * 8):
            with self.assertRaises(CSPRNGError):
                generate_random_bytes(16)

    def test_does_not_use_random_module(self):  # RNG-4
        path = os.path.join(os.path.dirname(__file__), "..", "src", "csprng.py")
        with open(path, encoding="utf-8") as f:
            source = f.read()
        self.assertNotIn("import random", source)
        self.assertNotIn("from random", source)


class TestWeakKey(unittest.TestCase):
    def test_weak_keys(self):
        for key_hex in (
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "000102030405060708090a0b0c0d0e0f",
            "0f0e0d0c0b0a09080706050403020100",
            "fafbfcfdfeff00010203040506070809",
            "abababababababababababababababab",
        ):
            with self.subTest(key=key_hex):
                self.assertIsNotNone(weak_key_reason(bytes.fromhex(key_hex)))

    def test_normal_keys(self):
        self.assertIsNone(weak_key_reason(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")))
        for _ in range(100):
            self.assertIsNone(weak_key_reason(generate_random_bytes(16)))


if __name__ == "__main__":
    unittest.main()
