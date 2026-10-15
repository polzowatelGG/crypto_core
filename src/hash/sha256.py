import struct

from .common import HashFunction

MASK = 0xFFFFFFFF
BLOCK_SIZE = 64  # 512 бит

# первые 32 бита дробных частей кубических корней первых 64 простых чисел (FIPS 180-4, 4.2.2)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# первые 32 бита дробных частей квадратных корней первых 8 простых чисел (FIPS 180-4, 5.3.3)
H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]



class SHA256(HashFunction):
    name = "sha256"
    digest_size = 32

    def __init__(self):
        self.h = list(H0)
        self.k = K
        self._buffer = b""   # хвост, не набравший целого блока
        self._length = 0     # длина всего сообщения в байтах

    def padding(self, message_len: int) -> bytes:
        # бит 1, затем нули до 448 mod 512, затем 64-битная длина сообщения в битах (big-endian)
        zeros = (55 - message_len) % BLOCK_SIZE
        return b"\x80" + b"\x00" * zeros + (message_len * 8).to_bytes(8, "big")

    def process_block(self, block: bytes) -> None:
        # ротации ROTR^n(x) = (x >> n) | (x << (32 - n)) раскрыты вручную ради скорости;
        # лишние старшие биты отсекаются маской суммы — младшие 32 бита сложения от них не зависят
        w = list(struct.unpack(">16I", block))
        for t in range(16, 64):  # расписание сообщения
            x, y = w[t - 15], w[t - 2]
            s0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)
            s1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & MASK)

        a, b, c, d, e, f, g, h = self.h
        for k, wt in zip(self.k, w):
            big_s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
            ch = (e & f) ^ (~e & g)
            t1 = h + big_s1 + ch + k + wt
            big_s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
            maj = (a & b) ^ (a & c) ^ (b & c)
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + big_s0 + maj) & MASK

        # Merkle-Damgard: новое состояние = старое + результат сжатия
        self.h = [(x + y) & MASK for x, y in zip(self.h, (a, b, c, d, e, f, g, h))]

    def update(self, message: bytes) -> "SHA256":
        self._length += len(message)
        data = self._buffer + message
        full = len(data) - len(data) % BLOCK_SIZE
        for i in range(0, full, BLOCK_SIZE):
            self.process_block(data[i:i + BLOCK_SIZE])
        self._buffer = data[full:]
        return self

    def digest(self) -> bytes:
        saved = self.h  # process_block заменяет список, поэтому состояние можно вернуть
        tail = self._buffer + self.padding(self._length)
        for i in range(0, len(tail), BLOCK_SIZE):
            self.process_block(tail[i:i + BLOCK_SIZE])
        result = struct.pack(">8I", *self.h)
        self.h = saved
        return result
