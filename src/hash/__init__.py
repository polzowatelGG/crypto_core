from .blake3 import BLAKE3
from .sha256 import SHA256
from .sha3_256 import SHA3_256

# имя для --algorithm -> класс реализации
ALGORITHMS = {
    SHA256.name: SHA256,
    SHA3_256.name: SHA3_256,
    BLAKE3.name: BLAKE3,
}
