from .common import check_iv, get_block_cipher, split_into_blocks, xor_bytes

# CFB с сегментом 128 бит (как aes-128-cfb в OpenSSL), без padding


def encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = get_block_cipher(key)
    prev = iv
    out = []
    for block in split_into_blocks(plaintext):
        prev = xor_bytes(block, cipher.encrypt(prev))  # C_i = P_i xor E_k(C_{i-1})
        out.append(prev)                               # неполный последний блок остаётся неполным
    return b"".join(out)


def decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = get_block_cipher(key)
    prev = iv
    out = []
    for block in split_into_blocks(ciphertext):
        out.append(xor_bytes(block, cipher.encrypt(prev)))  # P_i = C_i xor E_k(C_{i-1})
        prev = block
    return b"".join(out)
