import unittest
from src.modes.ecb import encrypt_ecb, decrypt_ecb, pkcs7_pad, pkcs7_unpad

TEST_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

class TestECB(unittest.TestCase):
    def test_encrypt_decrypt(self):
        plaintext = b"Hello, CryptoCore!"
        ciphertext = encrypt_ecb(plaintext, TEST_KEY)
        decrypted_plaintext = decrypt_ecb(ciphertext, TEST_KEY)
        self.assertEqual(decrypted_plaintext, plaintext)

    def test_short_plaintext(self):
        plaintext = b"Short"
        padded_plaintext = pkcs7_pad(plaintext)
        ciphertext = encrypt_ecb(plaintext, TEST_KEY)
        decrypted_plaintext = decrypt_ecb(ciphertext, TEST_KEY)

        self.assertEqual(padded_plaintext, b"Short\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
        self.assertEqual(decrypted_plaintext , plaintext) 
        
    def test_encrypt_wrong_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_ecb(b"some data", b"short_key")  # явно не 16 байт
            
    def test_pad_full_extra_block_when_already_aligned(self):
        plaintext = b"YYYYYYYYYYYYYYYY"  # ровно 16 байт — посчитай сам, если нужно
        padded = pkcs7_pad(plaintext)
        self.assertEqual(len(padded), 32)