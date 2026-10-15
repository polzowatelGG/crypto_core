from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="0.4.0",
    description="Минималистичный CLI-инструмент: шифрование файлов AES-128 (ECB, CBC, CFB, OFB, CTR; CSPRNG-генерация ключей) и хеширование (SHA-256, SHA3-256, BLAKE3)",
    packages=find_packages(include=["src", "src.*"]),
    install_requires=[
        "pycryptodome>=3.20",
    ],
    entry_points={
        "console_scripts": [
            "cryptocore=src.cli_parser:main",
        ],
    },
    python_requires=">=3.9",
)
