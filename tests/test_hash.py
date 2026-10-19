import hashlib
import os
import tempfile
import tracemalloc
import unittest

from src.file_io import CHUNK_SIZE, iter_input_chunks
from src.hash import BLAKE3, SHA256, SHA3_256
from src.hash.sha256 import MAX_MESSAGE_LEN

MSG_448 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
MSG_896 = (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
           b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
MILLION_A = b"a" * 1_000_000

# векторы NIST (FIPS 180-4 / FIPS 202 examples)
NIST_VECTORS = {
    SHA256: [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (MSG_448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (MSG_896, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
        (MILLION_A, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ],
    SHA3_256: [
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        (MSG_448, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
        (MSG_896, "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"),
        (MILLION_A, "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
    ],
}

# официальные векторы BLAKE3 (test_vectors.json): вход — байты i % 251 длины n
BLAKE3_VECTORS = {
    0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    63: "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    64: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    65: "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
    1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    2049: "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
    3072: "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
    3073: "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
    4096: "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
    4097: "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
    8193: "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b",
    16384: "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4",
}

ALL = [SHA256, SHA3_256, BLAKE3]


def blake3_input(n):
    return bytes(i % 251 for i in range(n))


class TestKnownAnswers(unittest.TestCase):  # TEST-1, TEST-2
    def test_nist_vectors(self):
        for cls, vectors in NIST_VECTORS.items():
            for data, expected in vectors:
                with self.subTest(algorithm=cls.name, length=len(data)):
                    self.assertEqual(cls().hash(data), expected)

    def test_blake3_vectors(self):
        for n, expected in BLAKE3_VECTORS.items():
            with self.subTest(length=n):
                self.assertEqual(BLAKE3().hash(blake3_input(n)), expected)


class TestStreaming(unittest.TestCase):  # HASH-4, HASH-5
    def test_chunked_update_matches_one_shot(self):
        data = blake3_input(5000)  # несколько блоков SHA, rate-блоков SHA3 и чанков BLAKE3
        for cls in ALL:
            for piece in (1, 7, 63, 64, 65, 136, 1024, 4096):
                with self.subTest(algorithm=cls.name, piece=piece):
                    h = cls()
                    for i in range(0, len(data), piece):
                        h.update(data[i:i + piece])
                    self.assertEqual(h.hexdigest(), cls().hash(data))

    def test_digest_does_not_change_state(self):
        for cls in ALL:
            with self.subTest(algorithm=cls.name):
                h = cls().update(b"hello ")
                h.digest()
                h.update(b"world")
                self.assertEqual(h.hexdigest(), cls().hash(b"hello world"))
                self.assertEqual(h.hexdigest(), h.hexdigest())

    def test_lowercase_hex(self):  # HASH-6
        for cls in ALL:
            with self.subTest(algorithm=cls.name):
                digest = cls().hash(b"abc")
                self.assertEqual(len(digest), 64)
                self.assertEqual(digest, digest.lower())


class TestAvalanche(unittest.TestCase):  # TEST-5
    def test_one_bit_flip(self):
        original = b"Hello, world!"
        modified = bytes([original[0] ^ 0x01]) + original[1:]
        for cls in ALL:
            with self.subTest(algorithm=cls.name):
                h1, h2 = int(cls().hash(original), 16), int(cls().hash(modified), 16)
                diff = bin(h1 ^ h2).count("1")
                self.assertTrue(100 < diff < 156, f"изменилось только {diff}/256 бит")

    def test_example_from_spec(self):  # пример из ТЗ: '!' -> '?'
        for cls in ALL:
            with self.subTest(algorithm=cls.name):
                h1 = int(cls().hash(b"Hello, world!"), 16)
                h2 = int(cls().hash(b"Hello, world?"), 16)
                diff = bin(h1 ^ h2).count("1")
                self.assertTrue(100 < diff < 156, f"изменилось только {diff}/256 бит")

    def test_average_over_every_bit_of_a_block(self):
        # каждый из 512 бит 64-байтного сообщения по очереди: среднее число изменившихся бит
        # должно быть ~128 (стандартное отклонение одного опыта 8, среднего по 512 — ~0.35)
        data = bytes(range(64))
        for cls in ALL:
            with self.subTest(algorithm=cls.name):
                base = int(cls().hash(data), 16)
                diffs = []
                for bit in range(len(data) * 8):
                    flipped = bytearray(data)
                    flipped[bit // 8] ^= 1 << (bit % 8)
                    diffs.append(bin(base ^ int(cls().hash(bytes(flipped)), 16)).count("1"))
                mean = sum(diffs) / len(diffs)
                self.assertTrue(126 < mean < 130, f"среднее {mean:.2f} бит из 256")
                self.assertGreater(min(diffs), 80)  # ни одного «слабого» бита


class TestAgainstReference(unittest.TestCase):  # TEST-1: все длины вокруг границ блоков
    # SHA-256: блок 64 байта, padding перестаёт помещаться в блок с 56 байт хвоста;
    # SHA3-256: rate 136 байт; BLAKE3: блок 64 байта, чанк 1024 байта
    LENGTHS = sorted({*range(0, 300), *range(1000, 1100), 2047, 2048, 2049, 3071, 3072, 3073})

    def check(self, cls, reference):
        data = os.urandom(max(self.LENGTHS))
        for n in self.LENGTHS:
            with self.subTest(algorithm=cls.name, length=n):
                self.assertEqual(cls().hash(data[:n]), reference(data[:n]))

    def test_sha256_matches_hashlib(self):
        self.check(SHA256, lambda d: hashlib.sha256(d).hexdigest())

    def test_sha3_256_matches_hashlib(self):
        self.check(SHA3_256, lambda d: hashlib.sha3_256(d).hexdigest())

    def test_blake3_matches_reference(self):
        try:
            import blake3
        except ImportError:
            self.skipTest("пакет blake3 не установлен (pip install blake3)")
        self.check(BLAKE3, lambda d: blake3.blake3(d).hexdigest())


class TestSHA256Padding(unittest.TestCase):  # HASH-1
    def test_padding_structure(self):
        for n in range(0, 200):
            with self.subTest(length=n):
                pad = SHA256().padding(n)
                self.assertEqual((n + len(pad)) % 64, 0)
                self.assertEqual(pad[0], 0x80)  # бит 1 сразу за сообщением
                self.assertEqual(pad[1:-8], b"\x00" * (len(pad) - 9))
                self.assertEqual(int.from_bytes(pad[-8:], "big"), n * 8)  # длина в битах
                self.assertLessEqual(len(pad), 72)  # не больше одного лишнего блока

    def test_extra_block_boundary(self):
        # 55 байт + 0x80 + 8 байт длины ровно в один блок, 56 байт уже требуют второго
        self.assertEqual(55 + len(SHA256().padding(55)), 64)
        self.assertEqual(56 + len(SHA256().padding(56)), 128)

    def test_message_length_limit(self):
        h = SHA256()
        h._length = MAX_MESSAGE_LEN
        h.update(b"")  # ровно на границе — допустимо
        with self.assertRaises(ValueError):
            h.update(b"a")


class TestConstantMemory(unittest.TestCase):  # HASH-5, IO-2
    def peak_memory(self, cls, size):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(size))
        self.addCleanup(os.remove, path)
        h = cls()
        tracemalloc.start()
        for chunk in iter_input_chunks(path):
            h.update(chunk)
        h.digest()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak

    def test_memory_does_not_grow_with_file_size(self):
        # у пика есть постоянная часть (~150 КБ: буферы open() и т. п.), поэтому сравниваем
        # два размера файла: при 8-кратном росте входа пик не должен заметно вырасти
        small, big = 64 * 1024, 512 * 1024
        for cls in ALL:
            with self.subTest(algorithm=cls.name):
                peak_small, peak_big = self.peak_memory(cls, small), self.peak_memory(cls, big)
                self.assertLess(peak_big, peak_small + 2 * CHUNK_SIZE,
                                f"пик {peak_small} -> {peak_big} байт при росте файла {small} -> {big}")
                self.assertLess(peak_big, big // 2)  # файл целиком в память не читается


if __name__ == "__main__":
    unittest.main()
