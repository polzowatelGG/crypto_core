from .common import (
    BLOCK_SIZE, check_iv, get_block_cipher, pkcs7_pad, pkcs7_unpad, split_into_blocks, xor_bytes,
)


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = get_block_cipher(key)
    prev = iv                                        # C_0 = IV
    out = []
    for block in split_into_blocks(pkcs7_pad(plaintext)):
        prev = cipher.encrypt(xor_bytes(block, prev))  # C_i = E_k(P_i xor C_{i-1})
        out.append(prev)
    return b"".join(out)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Длина шифртекста CBC должна быть ненулевой и кратной 16 байтам")
    cipher = get_block_cipher(key)
    prev = iv
    out = []
    for block in split_into_blocks(ciphertext):
        out.append(xor_bytes(cipher.decrypt(block), prev))  # P_i = D_k(C_i) xor C_{i-1}
        prev = block
    return pkcs7_unpad(b"".join(out))
