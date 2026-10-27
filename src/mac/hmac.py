from ..hash import ALGORITHMS
from ..modes.common import xor_bytes

IPAD = 0x36
OPAD = 0x5C


class HMAC:
    """HMAC по RFC 2104: HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))."""

    def __init__(self, key: bytes, hash_function: str = "sha256"):
        if hash_function not in ALGORITHMS:
            raise ValueError(f"неизвестная хеш-функция '{hash_function}'.")
        self.hash_function = ALGORITHMS[hash_function]
        self.block_size = self.hash_function.block_size  # 64 байта для SHA-256
        self.digest_size = self.hash_function.digest_size
        self.key = self._process_key(key)
        # MAC-3: внутренний хеш начинается с K' xor ipad, дальше сообщение подаётся через update()
        self._inner = self.hash_function().update(xor_bytes(self.key, bytes([IPAD]) * self.block_size))

    def _process_key(self, key: bytes) -> bytes:
        # MAC-2: длинный ключ сначала хешируется, короткий дополняется нулями до размера блока
        if len(key) > self.block_size:
            key = self.hash_function().update(key).digest()
        return key + b"\x00" * (self.block_size - len(key))

    def update(self, data: bytes) -> "HMAC":
        # MAC-5: сообщение можно подавать по частям, память не растёт
        self._inner.update(data)
        return self

    def digest(self) -> bytes:
        inner_hash = self._inner.digest()  # digest() не портит состояние, update() можно продолжать
        outer = self.hash_function().update(xor_bytes(self.key, bytes([OPAD]) * self.block_size))
        return outer.update(inner_hash).digest()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def compute(self, message: bytes) -> str:
        # интерфейс из ТЗ: HMAC целого сообщения в hex
        return self.update(message).hexdigest()
