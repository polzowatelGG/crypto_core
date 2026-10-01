import os
import unittest
from Crypto.Cipher import AES
from src.modes.cbc import encrypt_cbc, decrypt_cbc
from src.modes.cfb import encrypt_cfb, decrypt_cfb
from src.modes.ofb import encrypt_ofb, decrypt_ofb
from src.modes.ctr import encrypt_ctr, decrypt_ctr
from src.modes.common import pkcs7_pad

# Тестовые векторы из NIST SP 800-38A (Appendix F), AES-128
NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_CTR_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
NIST_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
NIST_CIPHERTEXTS = {
    "cbc": "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
           "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
    "cfb": "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
           "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
    "ofb": "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
           "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
    "ctr": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
           "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
}

MODES = {
    "cbc": (encrypt_cbc, decrypt_cbc),
    "cfb": (encrypt_cfb, decrypt_cfb),
    "ofb": (encrypt_ofb, decrypt_ofb),
    "ctr": (encrypt_ctr, decrypt_ctr),
}

TEST_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
TEST_IV = bytes.fromhex("aabbccddeeff00112233445566778899")
# длины: пустой, неполный блок, ровно блок, блок+хвост, несколько блоков
LENGTHS = [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000]


def reference(mode: str, key: bytes, iv: bytes):
    # эталонная реализация pycryptodome — используется ТОЛЬКО в тестах
    if mode == "cbc":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    if mode == "cfb":
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    if mode == "ofb":
        return AES.new(key, AES.MODE_OFB, iv=iv)
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)


class TestNISTVectors(unittest.TestCase):
    def test_encrypt_matches_nist(self):
        for mode, (encrypt, _) in MODES.items():
            with self.subTest(mode=mode):
                iv = NIST_CTR_IV if mode == "ctr" else NIST_IV
                ciphertext = encrypt(NIST_PLAINTEXT, NIST_KEY, iv)
                # в CBC добавляется ещё один блок padding — сверяем первые 64 байта
                self.assertEqual(ciphertext[:64].hex(), NIST_CIPHERTEXTS[mode])

    def test_decrypt_matches_nist(self):
        for mode in ("cfb", "ofb", "ctr"):
            with self.subTest(mode=mode):
                iv = NIST_CTR_IV if mode == "ctr" else NIST_IV
                _, decrypt = MODES[mode]
                self.assertEqual(decrypt(bytes.fromhex(NIST_CIPHERTEXTS[mode]), NIST_KEY, iv), NIST_PLAINTEXT)


class TestModes(unittest.TestCase):
    def test_round_trip(self):
        for mode, (encrypt, decrypt) in MODES.items():
            for n in LENGTHS:
                with self.subTest(mode=mode, length=n):
                    plaintext = os.urandom(n)
                    self.assertEqual(decrypt(encrypt(plaintext, TEST_KEY, TEST_IV), TEST_KEY, TEST_IV), plaintext)

    def test_matches_reference_implementation(self):
        for mode, (encrypt, _) in MODES.items():
            for n in LENGTHS:
                with self.subTest(mode=mode, length=n):
                    plaintext = os.urandom(n)
                    ref = reference(mode, TEST_KEY, TEST_IV)
                    if mode == "cbc":
                        expected = ref.encrypt(pkcs7_pad(plaintext))
                    else:
                        expected = ref.encrypt(plaintext)
                    self.assertEqual(encrypt(plaintext, TEST_KEY, TEST_IV), expected)

    def test_stream_modes_keep_length(self):
        for mode in ("cfb", "ofb", "ctr"):
            encrypt, _ = MODES[mode]
            for n in LENGTHS:
                with self.subTest(mode=mode, length=n):
                    self.assertEqual(len(encrypt(b"x" * n, TEST_KEY, TEST_IV)), n)

    def test_cbc_is_padded(self):
        self.assertEqual(len(encrypt_cbc(b"x" * 15, TEST_KEY, TEST_IV)), 16)
        self.assertEqual(len(encrypt_cbc(b"x" * 16, TEST_KEY, TEST_IV)), 32)

    def test_cbc_rejects_bad_ciphertext_length(self):
        with self.assertRaises(ValueError):
            decrypt_cbc(b"x" * 17, TEST_KEY, TEST_IV)

    def test_ctr_counter_wraps_around(self):
        iv = b"\xff" * 16
        plaintext = os.urandom(48)
        ref = reference("ctr", TEST_KEY, iv)
        self.assertEqual(encrypt_ctr(plaintext, TEST_KEY, iv), ref.encrypt(plaintext))

    def test_wrong_iv_length(self):
        for mode, (encrypt, decrypt) in MODES.items():
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    encrypt(b"data", TEST_KEY, b"short")
                with self.assertRaises(ValueError):
                    decrypt(b"data" * 4, TEST_KEY, b"short")


if __name__ == "__main__":
    unittest.main()
