from ..modes.common import BLOCK_SIZE, get_block_cipher, xor_bytes

RB = 0x87  # константа R_128 из NIST SP 800-38B, 5.3


def _double(block: bytes) -> bytes:
    # умножение на x в GF(2^128): сдвиг влево на бит, при выпавшей единице — XOR с R_128
    value = int.from_bytes(block, "big") << 1
    if value >> 128:
        value = (value & ((1 << 128) - 1)) ^ RB
    return value.to_bytes(BLOCK_SIZE, "big")


class CMAC:
    """AES-CMAC по NIST SP 800-38B (OMAC1): CBC-MAC, последний блок XOR-ится с подключом K1 или K2."""

    name = "cmac"
    digest_size = BLOCK_SIZE

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError(f"для AES-128-CMAC нужен ключ 16 байт, получено {len(key)}.")
        self._cipher = get_block_cipher(key)
        # генерация подключей (SP 800-38B, 6.1): L = AES_K(0^128), K1 = 2L, K2 = 4L
        l_block = self._cipher.encrypt(b"\x00" * BLOCK_SIZE)
        self.k1 = _double(l_block)
        self.k2 = _double(self.k1)
        self._state = b"\x00" * BLOCK_SIZE
        self._buffer = b""  # последний блок не шифруется, пока неизвестно, последний ли он

    def update(self, data: bytes) -> "CMAC":
        data = self._buffer + data
        # оставляем в буфере от 1 до 16 байт: полный блок в конце может оказаться последним
        keep = (len(data) % BLOCK_SIZE or BLOCK_SIZE) if data else 0
        for i in range(0, len(data) - keep, BLOCK_SIZE):
            self._state = self._cipher.encrypt(xor_bytes(self._state, data[i:i + BLOCK_SIZE]))
        self._buffer = data[len(data) - keep:]
        return self

    def digest(self) -> bytes:
        if len(self._buffer) == BLOCK_SIZE:  # полный последний блок: M_n xor K1
            last = xor_bytes(self._buffer, self.k1)
        else:  # неполный (или пустое сообщение): padding 10*, затем xor K2
            padded = self._buffer + b"\x80" + b"\x00" * (BLOCK_SIZE - len(self._buffer) - 1)
            last = xor_bytes(padded, self.k2)
        return self._cipher.encrypt(xor_bytes(self._state, last))

    def hexdigest(self) -> str:
        return self.digest().hex()

    def compute(self, message: bytes) -> str:
        return self.update(message).hexdigest()
