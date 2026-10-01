from Crypto.Cipher import AES

BLOCK_SIZE = 16 


def get_block_cipher(key: bytes):
    return AES.new(key, AES.MODE_ECB)


def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Некорректная длина данных для снятия padding")

    pad_len = data[-1]  # последний байт — заявленная длина padding

    if pad_len == 0 or pad_len > BLOCK_SIZE:
        raise ValueError("Некорректное значение padding байта")

    padding = data[-pad_len:]  # последние pad_len байт
    if padding != bytes([pad_len]) * pad_len:
        raise ValueError("Padding повреждён: байты не совпадают")

    return data[:-pad_len]


def split_into_blocks(data: bytes) -> list[bytes]:
    # последний блок может быть неполным — это нужно потоковым режимам
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    # XOR по длине более короткого аргумента (для неполного последнего блока)
    return bytes(x ^ y for x, y in zip(a, b))


def check_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV должен быть длиной {BLOCK_SIZE} байт, получено {len(iv)}.")
