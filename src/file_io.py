import sys

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