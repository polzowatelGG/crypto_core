from .common import get_block_cipher, pkcs7_pad, pkcs7_unpad, split_into_blocks, BLOCK_SIZE

def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Длина шифртекста ECB должна быть кратна 16 байтам")
    blocks = split_into_blocks(ciphertext)          # шифртекст уже кратен 16, без pad
    cipher = get_block_cipher(key)                   # сначала создать cipher
    padded_plaintext = b"".join(cipher.decrypt(block) for block in blocks)  # расшифровать каждый блок
    return pkcs7_unpad(padded_plaintext)              # и только теперь снять padding


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    padded_plaintext = pkcs7_pad(plaintext)          # сначала добавить padding
    blocks = split_into_blocks(padded_plaintext)     # затем разбить на блоки
    cipher = get_block_cipher(key)                   # создать cipher
    return b"".join(cipher.encrypt(block) for block in blocks)  # зашифровать каждый блок
