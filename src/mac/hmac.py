from ..hash import ALGORITHMS
from ..modes.common import xor_bytes

IPAD = 0x36
OPAD = 0x5C


def get_hash_function(name: str):
    # класс собственной хеш-функции из src/hash по имени (MAC-1: SHA-256 из спринта 4)
    if name not in ALGORITHMS:
        raise ValueError(f"неизвестная хеш-функция '{name}', доступны: {', '.join(ALGORITHMS)}.")
    return ALGORITHMS[name]


class HMAC:
    """HMAC по RFC 2104: HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m)).

    Два способа использования:
    - compute(message) — HMAC одного целого сообщения, объект при этом не меняется;
    - update(chunk)... + digest()/hexdigest() — сообщение по частям (MAC-5, файлы любого размера).
    """

    def __init__(self, key: bytes, hash_function: str = "sha256"):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f"ключ HMAC должен быть bytes, получено {type(key).__name__}.")
        self.hash_function = get_hash_function(hash_function)
        self.block_size = self.hash_function.block_size  # 64 байта для SHA-256
        self.digest_size = self.hash_function.digest_size
        self.key = self._process_key(bytes(key))
        # MAC-3: K' xor ipad и K' xor opad не зависят от сообщения — считаем один раз
        self._ipad_key = xor_bytes(self.key, bytes([IPAD]) * self.block_size)
        self._opad_key = xor_bytes(self.key, bytes([OPAD]) * self.block_size)
        self._inner = self.hash_function().update(self._ipad_key)

    def _process_key(self, key: bytes) -> bytes:
        # MAC-2, MAC-4: ключ любой длины; длиннее блока — сначала хешируется,
        # затем (в том числе H(K)) дополняется нулями до размера блока
        if len(key) > self.block_size:
            key = self.hash_function().update(key).digest()
        return key + b"\x00" * (self.block_size - len(key))

    def _outer(self, inner_hash: bytes) -> bytes:
        # внешний хеш: H((K' xor opad) || inner_hash)
        return self.hash_function().update(self._opad_key).update(inner_hash).digest()

    def update(self, data: bytes) -> "HMAC":
        # MAC-5: сообщение подаётся по частям, хеш хранит лишь неполный блок — память не растёт
        self._inner.update(data)
        return self

    def digest(self) -> bytes:
        # digest() хеш-функции не портит состояние, поэтому после digest() можно продолжать update()
        return self._outer(self._inner.digest())

    def hexdigest(self) -> str:
        return self.digest().hex()

    def compute(self, message: bytes) -> str:
        # интерфейс из ТЗ: HMAC целого сообщения в hex; потоковое состояние не затрагивается
        inner_hash = self.hash_function().update(self._ipad_key).update(message).digest()
        return self._outer(inner_hash).hex()
