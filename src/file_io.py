import os
import sys
from typing import Iterator, NoReturn

CHUNK_SIZE = 8192


def _exit_on_read_error(path: str, e: OSError) -> NoReturn:
    if isinstance(e, FileNotFoundError):
        message = f"входной файл '{path}' не найден."
    elif isinstance(e, PermissionError):
        message = f"нет прав на чтение файла '{path}'."
    elif isinstance(e, IsADirectoryError):
        message = f"'{path}' — это каталог, а не файл."
    else:
        message = f"не удалось прочитать файл '{path}': {e.strerror or e}."
    print(f"Ошибка: {message}", file=sys.stderr)
    sys.exit(1)


def _exit_on_write_error(path: str, e: OSError) -> NoReturn:
    if isinstance(e, FileNotFoundError):
        message = f"каталог для выходного файла '{path}' не существует."
    elif isinstance(e, PermissionError):
        message = f"нет прав на запись в файл '{path}'."
    elif isinstance(e, IsADirectoryError):
        message = f"'{path}' — это каталог, а не файл."
    else:
        message = f"не удалось записать файл '{path}': {e.strerror or e}."
    print(f"Ошибка: {message}", file=sys.stderr)
    sys.exit(1)


def read_input_file(input_path: str) -> bytes:
    try:
        with open(input_path, "rb") as f:
            return f.read()
    except OSError as e:
        _exit_on_read_error(input_path, e)


def iter_input_chunks(input_path: str, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    # IO-1, IO-2: бинарное чтение по частям; '-' — стандартный ввод
    try:
        if input_path == "-":
            while chunk := sys.stdin.buffer.read(chunk_size):
                yield chunk
            return
        with open(input_path, "rb") as f:
            while chunk := f.read(chunk_size):
                yield chunk
    except OSError as e:
        _exit_on_read_error(input_path, e)


def write_output_file(output_path: str, data: bytes) -> None:
    try:
        with open(output_path, "wb") as f:
            f.write(data)
    except OSError as e:
        _exit_on_write_error(output_path, e)


def write_stdout(data: bytes) -> None:
    # байты, а не текст: вывод не зависит от кодировки терминала и совпадает с записью в файл
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
    except BrokenPipeError:
        # читатель закрыл канал (например, '| head'): выходим без traceback, как *sum-утилиты;
        # stdout перенаправляется в devnull, чтобы Python не упал повторно при финальном flush
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)


def is_same_file(input_path: str, output_path: str) -> bool:
    # samefile учитывает символические и жёсткие ссылки, а не только совпадение строк
    if input_path == "-":
        return False
    try:
        return os.path.samefile(input_path, output_path)
    except OSError:  # одного из файлов нет — значит, это не один файл
        return False
