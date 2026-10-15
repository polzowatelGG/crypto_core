import sys
from typing import Iterator

CHUNK_SIZE = 8192


def read_input_file(input_path: str) -> bytes:
    try:
        with open(input_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Ошибка: входной файл '{input_path}' не найден.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Ошибка: нет прав на чтение файла '{input_path}'.", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Ошибка: '{input_path}' — это каталог, а не файл.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Ошибка при чтении файла '{input_path}': {e}", file=sys.stderr)
        sys.exit(1)


def iter_input_chunks(input_path: str, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    # бинарное чтение по частям; '-' — стандартный ввод
    try:
        if input_path == "-":
            while chunk := sys.stdin.buffer.read(chunk_size):
                yield chunk
            return
        with open(input_path, "rb") as f:
            while chunk := f.read(chunk_size):
                yield chunk
    except FileNotFoundError:
        print(f"Ошибка: входной файл '{input_path}' не найден.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Ошибка: нет прав на чтение файла '{input_path}'.", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Ошибка: '{input_path}' — это каталог, а не файл.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Ошибка при чтении файла '{input_path}': {e}", file=sys.stderr)
        sys.exit(1)


def write_output_file(output_path: str, data: bytes) -> None:
    try:
        with open(output_path, "wb") as f:
            f.write(data)
    except PermissionError:
        print(f"Ошибка: нет прав на запись в файл '{output_path}'.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Ошибка при записи в файл '{output_path}': {e}", file=sys.stderr)
        sys.exit(1)
