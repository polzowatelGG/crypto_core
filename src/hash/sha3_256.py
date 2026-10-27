from .common import HashFunction

MASK64 = (1 << 64) - 1
RATE = 136  # байт: 1600 - 2*256 бит ёмкости = 1088 бит


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK64


def _rho_offsets() -> list[int]:
    # FIPS 202, 3.2.2: смещения rho для дорожки x + 5*y
    offsets = [0] * 25
    x, y = 1, 0
    for t in range(24):
        offsets[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


def _round_constants() -> list[int]:
    # FIPS 202, 3.2.5: константы iota из LFSR x^8 + x^6 + x^5 + x^4 + 1
    constants = []
    r = 1
    for _ in range(24):
        rc = 0
        for j in range(7):
            if r & 1:
                rc |= 1 << ((1 << j) - 1)
            r = ((r << 1) ^ ((r >> 7) * 0x71)) & 0xFF
        constants.append(rc)
    return constants


RHO = _rho_offsets()
RC = _round_constants()

# rho и pi: B[y, 2x+3y] = ROT(A[x, y], RHO[x, y]) — тройки (откуда, куда, сдвиг)
RHO_PI = [(x + 5 * y, y + 5 * ((2 * x + 3 * y) % 5), RHO[x + 5 * y]) for y in range(5) for x in range(5)]
# chi: A[x, y] = B[x, y] ^ (~B[x+1, y] & B[x+2, y]) — тройки индексов
CHI = [(x + 5 * y, (x + 1) % 5 + 5 * y, (x + 2) % 5 + 5 * y) for y in range(5) for x in range(5)]


def keccak_f1600(a: list[int]) -> list[int]:
    b = [0] * 25
    for rc in RC:
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        # theta + rho + pi за один проход
        for src, dst, r in RHO_PI:
            v = a[src] ^ d[src % 5]
            b[dst] = ((v << r) | (v >> (64 - r))) & MASK64
        # chi
        a = [b[i] ^ (~b[j] & b[k]) for i, j, k in CHI]
        # iota
        a[0] ^= rc
    return a


class SHA3_256(HashFunction):
    name = "sha3-256"
    digest_size = 32
    block_size = RATE  # для HMAC-SHA3 блоком считается rate (FIPS 202, NIST SP 800-224)

    def __init__(self):
        self._state = [0] * 25  # 5x5 дорожек по 64 бита
        self._buffer = b""

    def _absorb_block(self, block: bytes) -> None:
        for i in range(RATE // 8):
            self._state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        self._state = keccak_f1600(self._state)

    def update(self, data: bytes) -> "SHA3_256":
        data = self._buffer + data
        full = len(data) - len(data) % RATE
        for i in range(0, full, RATE):
            self._absorb_block(data[i:i + RATE])
        self._buffer = data[full:]
        return self

    def digest(self) -> bytes:
        saved = list(self._state)  # _absorb_block меняет список на месте
        # pad10*1 с суффиксом домена SHA-3 '01': первый байт 0x06, последний бит 0x80
        block = bytearray(self._buffer + b"\x06" + b"\x00" * (RATE - len(self._buffer) - 1))
        block[-1] |= 0x80
        self._absorb_block(bytes(block))
        out = b"".join(lane.to_bytes(8, "little") for lane in self._state[:4])  # squeeze: 256 бит
        self._state = saved
        return out
