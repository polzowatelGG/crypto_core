import struct

from .common import HashFunction

MASK = 0xFFFFFFFF
BLOCK_LEN = 64
CHUNK_LEN = 1024

# флаги доменного разделения
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]


# позиции функции G в раунде: 4 столбца, затем 4 диагонали матрицы состояния 4x4
G_POSITIONS = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
               (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]


def _schedule() -> list[list[tuple]]:
    # перестановка слов сообщения между раундами заранее сведена в индексы: m'[i] = m[P[i]]
    rounds, order = [], list(range(16))
    for _ in range(7):
        rounds.append([(G_POSITIONS[i], order[2 * i], order[2 * i + 1]) for i in range(8)])
        order = [order[i] for i in MSG_PERMUTATION]
    return rounds


SCHEDULE = _schedule()


def compress(cv: list[int], block_words: list[int], counter: int, block_len: int, flags: int) -> list[int]:
    s = [*cv, *IV[:4], counter & MASK, (counter >> 32) & MASK, block_len, flags]
    m = block_words
    for rnd in SCHEDULE:
        for (a, b, c, d), mx, my in rnd:
            # функция G; ROTR^n раскрыта вручную ради скорости
            va = (s[a] + s[b] + m[mx]) & MASK
            vd = s[d] ^ va
            vd = ((vd >> 16) | (vd << 16)) & MASK
            vc = (s[c] + vd) & MASK
            vb = s[b] ^ vc
            vb = ((vb >> 12) | (vb << 20)) & MASK
            va = (va + vb + m[my]) & MASK
            vd ^= va
            vd = ((vd >> 8) | (vd << 24)) & MASK
            vc = (vc + vd) & MASK
            vb ^= vc
            vb = ((vb >> 7) | (vb << 25)) & MASK
            s[a], s[b], s[c], s[d] = va, vb, vc, vd
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block: bytes) -> list[int]:
    return list(struct.unpack("<16I", block.ljust(BLOCK_LEN, b"\x00")))


class _Output:
    """Последний вызов compress узла дерева; ROOT-флаг добавляется только для корня."""

    def __init__(self, cv, block_words, counter, block_len, flags):
        self.cv, self.block_words, self.counter = cv, block_words, counter
        self.block_len, self.flags = block_len, flags

    def chaining_value(self) -> list[int]:
        return compress(self.cv, self.block_words, self.counter, self.block_len, self.flags)[:8]

    def root_bytes(self, length: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < length:
            words = compress(self.cv, self.block_words, counter, self.block_len, self.flags | ROOT)
            out += struct.pack("<16I", *words)
            counter += 1
        return out[:length]


class _ChunkState:
    def __init__(self, key_words: list[int], chunk_counter: int):
        self.cv = list(key_words)
        self.chunk_counter = chunk_counter
        self.block = b""
        self.blocks_compressed = 0

    def __len__(self) -> int:
        return BLOCK_LEN * self.blocks_compressed + len(self.block)

    def _start_flag(self) -> int:
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: bytes) -> None:
        while data:
            # полный блок сжимаем, только когда пришли ещё данные: последний блок чанка нужен с CHUNK_END
            if len(self.block) == BLOCK_LEN:
                self.cv = compress(self.cv, _words(self.block), self.chunk_counter,
                                   BLOCK_LEN, self._start_flag())[:8]
                self.blocks_compressed += 1
                self.block = b""
            take = BLOCK_LEN - len(self.block)
            self.block += data[:take]
            data = data[take:]

    def output(self) -> _Output:
        return _Output(self.cv, _words(self.block), self.chunk_counter, len(self.block),
                       self._start_flag() | CHUNK_END)


def _parent_output(left: list[int], right: list[int], key_words: list[int]) -> _Output:
    return _Output(key_words, left + right, 0, BLOCK_LEN, PARENT)


class BLAKE3(HashFunction):
    name = "blake3"
    block_size = BLOCK_LEN
    digest_size = 32

    def __init__(self):
        self._key = IV
        self._chunk = _ChunkState(self._key, 0)
        self._cv_stack: list[list[int]] = []  # CV готовых поддеревьев (дерево Меркла по чанкам)

    def _add_chunk_cv(self, cv: list[int], total_chunks: int) -> None:
        # каждый нулевой младший бит total_chunks — завершённое поддерево, сливаем его с соседом
        while total_chunks & 1 == 0:
            cv = _parent_output(self._cv_stack.pop(), cv, self._key).chaining_value()
            total_chunks >>= 1
        self._cv_stack.append(cv)

    def update(self, data: bytes) -> "BLAKE3":
        data = memoryview(data)
        while data:
            # полный чанк закрываем, только когда есть продолжение: последний чанк может оказаться корнем
            if len(self._chunk) == CHUNK_LEN:
                cv = self._chunk.output().chaining_value()
                total = self._chunk.chunk_counter + 1
                self._add_chunk_cv(cv, total)
                self._chunk = _ChunkState(self._key, total)
            take = CHUNK_LEN - len(self._chunk)
            self._chunk.update(bytes(data[:take]))
            data = data[take:]
        return self

    def digest(self) -> bytes:
        output = self._chunk.output()
        for cv in reversed(self._cv_stack):
            output = _parent_output(cv, output.chaining_value(), self._key)
        return output.root_bytes(self.digest_size)
