# Генерация бинарного файла для NIST Statistical Test Suite.
# Запуск из корня проекта:
#     python3 -m tests.generate_nist_data [путь] [размер_в_байтах]
# По умолчанию — nist_test_data.bin размером 12 500 000 байт
# (= 100 последовательностей по 1 000 000 бит, стандартная конфигурация STS).
import sys
from src.csprng import generate_random_bytes

DEFAULT_PATH = "nist_test_data.bin"
DEFAULT_SIZE = 100 * 1_000_000 // 8
CHUNK_SIZE = 4096

def generate_file(path: str, total_size: int) -> None:
    written = 0
    with open(path, "wb") as f:
        while written < total_size:
            chunk = generate_random_bytes(min(CHUNK_SIZE, total_size - written))
            f.write(chunk)
            written += len(chunk)
    print(f"Сгенерировано {written} байт ({written * 8} бит) в '{path}'")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH
    size = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_SIZE
    generate_file(path, size)
