import argparse
import os
import sys
from typing import Iterator, Optional
from .csprng import CSPRNGError, generate_random_bytes
from .file_io import iter_input_chunks, read_input_file, write_output_file
from .hash import ALGORITHMS
from .modes.common import BLOCK_SIZE
from .modes.ecb import encrypt_ecb, decrypt_ecb
from .modes.cbc import encrypt_cbc, decrypt_cbc
from .modes.cfb import encrypt_cfb, decrypt_cfb
from .modes.ofb import encrypt_ofb, decrypt_ofb
from .modes.ctr import encrypt_ctr, decrypt_ctr

# режимы, которым нужен IV: (функция шифрования, функция расшифрования)
IV_MODES = {
    "cbc": (encrypt_cbc, decrypt_cbc),
    "cfb": (encrypt_cfb, decrypt_cfb),
    "ofb": (encrypt_ofb, decrypt_ofb),
    "ctr": (encrypt_ctr, decrypt_ctr),
}

# аргументы, которые есть только у шифрования (CLI-3 спринта 4: dgst их не принимает)
ENC_ONLY_OPTIONS = ("--mode", "--encrypt", "--decrypt", "--key", "--iv")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Минималистический криптографический провайдер (CryptoCore). "
                    "Шифрование/расшифрование файлов; для хеширования: cryptocore dgst --help.",
        allow_abbrev=False,  # иначе argparse молча принимает сокращения вроде --enc или --k
    )

    parser.add_argument(
        "--algorithm", #выбор алгоритма шифрования
        required=True,
        choices=["aes"],
        help="Шифр для использования.", #пока что только AES
    )
    parser.add_argument(
        "--mode", #выбор режима работы блочного шифра
        required=True,
        choices=["ecb", *IV_MODES],
        help="Режим работы блочного шифра.",
    )

    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument(
        "--encrypt", action="store_true", help="Зашифровать входной файл." #выбор операции шифрования
    )
    operation_group.add_argument(
        "--decrypt", action="store_true", help="Расшифровать входной файл." #и расшифрования
    )

    parser.add_argument(
        "--key",
        required=False,
        help="Ключ в виде hex-строки (32 hex-символа = 16 байт для AES-128). "
             "Обязателен для --decrypt; при --encrypt без --key ключ генерируется и выводится в stdout.",
    )
    parser.add_argument(
        "--iv",
        required=False,
        help="IV в виде hex-строки (32 hex-символа). Только для --decrypt; "
             "если не указан, IV читается из первых 16 байт входного файла.",
    )
    parser.add_argument(
        "--input", required=True, dest="input_path", help="Путь к входному файлу." #уточнение формата входного файла
    )
    parser.add_argument(
        "--output", required=False, dest="output_path", help="Путь к выходному файлу." #уточнение формата выходного файла
    )

    return parser

def build_dgst_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Вычисление message digest (хеша) файла.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--algorithm", required=True, choices=list(ALGORITHMS), help="Хеш-функция.",
    )
    parser.add_argument(
        "--input", required=True, dest="input_path",
        help="Путь к входному файлу ('-' — стандартный ввод).",
    )
    parser.add_argument(
        "--output", required=False, dest="output_path",
        help="Записать хеш в файл вместо stdout (в том же формате).",
    )
    return parser

def option_names(argv: list[str]) -> Iterator[str]:
    # имена длинных опций из командной строки, в том числе в форме --opt=value
    for token in argv:
        if token.startswith("--"):
            yield token.split("=", 1)[0]

def reject_duplicate_options(parser: argparse.ArgumentParser, argv: list[str]) -> None:
    # argparse молча берёт последнее значение повторённой опции — считаем это ошибкой
    seen = set()
    for name in option_names(argv):
        if name in seen:
            parser.error(f"аргумент {name} указан несколько раз.")
        seen.add(name)

def format_digest_line(digest_hex: str, path: str) -> str:
    # CLI-4: формат *sum-утилит 'HASH  PATH'; как в coreutils, обратный слэш и перевод строки
    # в имени экранируются, а сама строка тогда начинается с обратного слэша
    if "\\" in path or "\n" in path:
        return "\\" + digest_hex + "  " + path.replace("\\", "\\\\").replace("\n", "\\n")
    return f"{digest_hex}  {path}"

def validate_key(key: str) -> bytes: #придумать проверку по длине и валидности
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        raise ValueError("Ключ должен быть в формате hex-строки.")
    if len(key_bytes) != 16:
        raise ValueError(f"Для AES-128 нужно 16 байт, получено {len(key_bytes)}.")
    return key_bytes

def weak_key_reason(key: bytes) -> Optional[str]:
    # CLI-5: простые эвристики для очевидно слабых ключей
    if len(set(key)) == 1:
        return f"все байты ключа одинаковые (0x{key[0]:02x})"
    steps = {(key[i + 1] - key[i]) % 256 for i in range(len(key) - 1)}
    if steps == {1}:
        return "байты ключа идут по возрастанию подряд"
    if steps == {255}:
        return "байты ключа идут по убыванию подряд"
    if len(set(key)) <= 2:
        return "ключ состоит всего из двух различных байт"
    return None

def validate_iv(iv: str) -> bytes:
    try:
        iv_bytes = bytes.fromhex(iv)
    except ValueError:
        raise ValueError("IV должен быть в формате hex-строки.")
    if len(iv_bytes) != BLOCK_SIZE:
        raise ValueError(f"IV должен быть длиной {BLOCK_SIZE} байт, получено {len(iv_bytes)}.")
    return iv_bytes

def input_file_exists(path: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Входной файл '{path}' не найден.")

def run_dgst(argv: list[str]) -> None:
    parser = build_dgst_parser()
    reject_duplicate_options(parser, argv)
    for name in option_names(argv):  # CLI-3: аргументы шифрования не принимаются
        if name in ENC_ONLY_OPTIONS:
            parser.error(f"аргумент {name} относится к шифрованию и не применим к команде dgst.")
    args = parser.parse_args(argv)

    hasher = ALGORITHMS[args.algorithm]()
    for chunk in iter_input_chunks(args.input_path):  # IO-2: по частям, память не растёт
        hasher.update(chunk)
    line = format_digest_line(hasher.hexdigest(), args.input_path) + "\n"

    if args.output_path:  # CLI-5, IO-3: в файл в том же формате, что и в stdout
        write_output_file(args.output_path, line.encode("utf-8", "surrogateescape"))
    else:
        sys.stdout.write(line)

def run_enc(argv: list[str]) -> None:
    parser = build_parser()
    reject_duplicate_options(parser, argv)
    args = parser.parse_args(argv)

    # CLI-3: при шифровании IV генерируется, передавать его нельзя
    if args.encrypt and args.iv is not None:
        parser.error("--iv допускается только при --decrypt (при шифровании IV генерируется автоматически).")
    if args.mode == "ecb" and args.iv is not None:
        parser.error("режим ECB не использует IV, --iv с ним недопустим.")

    # CLI-4: без ключа расшифровать нельзя
    if args.decrypt and args.key is None:
        parser.error("--key обязателен при --decrypt.")

    try:
        key_bytes = validate_key(args.key) if args.key is not None else None
        iv_bytes = validate_iv(args.iv) if args.iv is not None else None
    except ValueError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)

    if key_bytes is not None:
        reason = weak_key_reason(key_bytes)
        if reason:
            print(f"[WARNING] Ключ выглядит слабым: {reason}. "
                  f"Для шифрования лучше не указывать --key — тогда ключ будет сгенерирован случайно.",
                  file=sys.stderr)

    output_path = args.output_path if args.output_path else (
        args.input_path + (".enc" if args.encrypt else ".dec")
    )

    data = read_input_file(args.input_path)

    try:
        if key_bytes is None:                                        # CLI-3: генерация ключа
            key_bytes = generate_random_bytes(16)                    # KEY-1: 16 байт для AES-128
            print(f"[INFO] Generated random key: {key_bytes.hex()}", flush=True)  # KEY-2: один раз, в stdout

        if args.mode == "ecb":
            result = encrypt_ecb(data, key_bytes) if args.encrypt else decrypt_ecb(data, key_bytes)
        elif args.encrypt:
            encrypt_fn, _ = IV_MODES[args.mode]
            iv_bytes = generate_random_bytes(BLOCK_SIZE)             # IV-1: CSPRNG
            result = iv_bytes + encrypt_fn(data, key_bytes, iv_bytes)  # IV-2: <IV><Ciphertext>
        else:
            _, decrypt_fn = IV_MODES[args.mode]
            if iv_bytes is None:                                     # IV-3: IV из начала файла
                if len(data) < BLOCK_SIZE:
                    raise ValueError(
                        f"входной файл слишком короткий ({len(data)} байт): "
                        f"нет полного {BLOCK_SIZE}-байтного IV в начале файла."
                    )
                iv_bytes, data = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
            result = decrypt_fn(data, key_bytes, iv_bytes)
    except ValueError as e:
        print(f"Ошибка при обработке данных: {e}", file=sys.stderr)
        sys.exit(1)
    except CSPRNGError as e:
        print(f"Ошибка генерации случайных данных: {e}", file=sys.stderr)
        sys.exit(1)

    write_output_file(output_path, result)

    if args.encrypt:
        print(f"Шифрование файла '{args.input_path}' в '{output_path}' с использованием алгоритма {args.algorithm} в режиме {args.mode}.")
        if args.mode != "ecb":
            print(f"IV (записан в начало выходного файла): {iv_bytes.hex()}")
    else:
        print(f"Расшифрование файла '{args.input_path}' в '{output_path}' с использованием алгоритма {args.algorithm} в режиме {args.mode}.")

def main(argv: Optional[list[str]] = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "dgst":  # CLI-1: подкоманда хеширования
        run_dgst(argv[1:])
    else:  # шифрование — без подкоманды, как в ТЗ спринтов 1–3
        run_enc(argv)

if __name__ == "__main__":
    main()
