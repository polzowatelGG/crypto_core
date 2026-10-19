"""TEST-6: время `cryptocore dgst` против системных утилит на файлах разного размера.

Запуск: python3 -m tests.bench_hash [размер_в_байтах ...]
Печатает таблицу в формате Markdown (её можно вставить в TESTING.md).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SIZES = [1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024]

# системная утилита для каждого алгоритма: первая найденная в PATH
SYSTEM_TOOLS = {
    "sha256": [["sha256sum"], ["shasum", "-a", "256"]],
    "sha3-256": [["sha3sum", "-a", "256"], ["openssl", "dgst", "-sha3-256", "-r"]],
    "blake3": [["b3sum"]],
}


def find_tool(algorithm):
    for cmd in SYSTEM_TOOLS[algorithm]:
        if shutil.which(cmd[0]):
            return cmd
    return None


def timed(cmd, cwd=None):
    start = time.perf_counter()
    subprocess.run(cmd, cwd=cwd, check=True, stdout=subprocess.DEVNULL)
    return time.perf_counter() - start


def human(size):
    for unit, factor in (("МБ", 1 << 20), ("КБ", 1 << 10)):
        if size >= factor:
            return f"{size / factor:g} {unit}"
    return f"{size} Б"


def main(sizes):
    print("| Алгоритм | Размер | CryptoCore, с | МБ/с | Системная утилита | Утилита, с | Во сколько раз медленнее |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    with tempfile.TemporaryDirectory() as tmp:
        for size in sizes:
            path = os.path.join(tmp, f"data_{size}.bin")
            with open(path, "wb") as f:
                f.write(os.urandom(size))
            for algorithm, _ in SYSTEM_TOOLS.items():
                ours = timed([sys.executable, "-m", "src.cli_parser", "dgst",
                              "--algorithm", algorithm, "--input", path], cwd=PROJECT_ROOT)
                tool = find_tool(algorithm)
                if tool is None:
                    tool_cell, theirs_cell, ratio_cell = "нет в системе", "—", "—"
                else:
                    theirs = timed([*tool, path])
                    tool_cell = f"`{' '.join(tool)}`"
                    theirs_cell, ratio_cell = f"{theirs:.3f}", f"{ours / theirs:.0f}×"
                speed = size / ours / (1 << 20)
                print(f"| {algorithm} | {human(size)} | {ours:.3f} | {speed:.2f} | {tool_cell} "
                      f"| {theirs_cell} | {ratio_cell} |", flush=True)


if __name__ == "__main__":
    main([int(s) for s in sys.argv[1:]] or DEFAULT_SIZES)
