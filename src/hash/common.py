class HashFunction:
    """Общий интерфейс хеш-функций: update() по частям, digest() — итог, состояние не портится."""

    name = ""
    digest_size = 0
    block_size = 0  # байт; нужен HMAC для выравнивания ключа

    def update(self, data: bytes) -> "HashFunction":
        raise NotImplementedError

    def digest(self) -> bytes:
        raise NotImplementedError

    def hexdigest(self) -> str:
        return self.digest().hex()  # HASH-6: hex в нижнем регистре

    def hash(self, data: bytes) -> str:
        self.update(data)
        return self.hexdigest()
