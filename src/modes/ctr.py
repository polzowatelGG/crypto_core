from .common import BLOCK_SIZE, check_iv, get_block_cipher, split_into_blocks, xor_bytes

# CTR: счётчик — 128-битное big-endian число, начальное значение = IV,
# увеличивается на 1 для каждого блока (по модулю 2^128, как в OpenSSL). Без padding.

def _ctr_process(data: bytes, key: bytes, iv: bytes) -> bytes:
    check_iv(iv)
    cipher = get_block_cipher(key)
    counter = int.from_bytes(iv, "big")
    out = []
    for block in split_into_blocks(data):
        keystream = cipher.encrypt(counter.to_bytes(BLOCK_SIZE, "big"))
        out.append(xor_bytes(block, keystream))
        counter = (counter + 1) % (1 << (8 * BLOCK_SIZE))
    return b"".join(out)


def encrypt_ctr(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return _ctr_process(plaintext, key, iv)


def decrypt_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # шифрование и расшифрование в CTR совпадают
    return _ctr_process(ciphertext, key, iv)
