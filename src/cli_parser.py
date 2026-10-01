import argparse
import os
import sys
from typing import Optional
from .csprng import CSPRNGError, generate_random_bytes
from .file_io import read_input_file, write_output_file
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

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Минималистический криптографический провайдер (CryptoCore).",
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

def main():
    parser = build_parser()
    args = parser.parse_args()

    # CLI-3: при шифровании IV генерируется, передавать его нельзя
    if args.encrypt and args.iv is not None:
        parser.error("--iv допускается только при --decrypt (при шифровании IV генерируется автоматически).")
    if args.mode == "ecb" and args.iv is not None:
        print("Предупреждение: режим ECB не использует IV, --iv проигнорирован.", file=sys.stderr)

    # CLI-4: без ключа расшифровать нельзя
    if args.decrypt and args.key is None:
        parser.error("--key обязателен при --decrypt.")

    try:
        key_bytes = validate_key(args.key) if args.key is not None else None
        iv_bytes = validate_iv(args.iv) if args.iv is not None and args.mode != "ecb" else None
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

if __name__ == "__main__":
    main()
