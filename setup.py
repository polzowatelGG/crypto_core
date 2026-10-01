from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="0.3.0",
    description="Минималистичный CLI-инструмент для блочного шифрования файлов (AES-128: ECB, CBC, CFB, OFB, CTR; CSPRNG-генерация ключей)",
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
