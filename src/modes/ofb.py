from .common import check_iv, get_block_cipher, split_into_blocks, xor_bytes

# OFB: гамма O_i = E_k(O_{i-1}), O_0 = IV — не зависит от открытого текста, без padding

def _ofb_process(data: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = get_block_cipher(key)
    keystream = iv
    out = []
    for block in split_into_blocks(data):
        keystream = cipher.encrypt(keystream)
        out.append(xor_bytes(block, keystream))
    return b"".join(out)


def encrypt_ofb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return _ofb_process(plaintext, key, iv)


def decrypt_ofb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # шифрование и расшифрование в OFB совпадают
    return _ofb_process(ciphertext, key, iv)
