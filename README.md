# CryptoCore

CLI-инструмент для шифрования и расшифрования файлов с помощью AES-128 в режимах ECB, CBC, CFB, OFB и CTR и для вычисления хешей файлов (SHA-256, SHA3-256, BLAKE3) — команда [`dgst`](#хеширование-команда-dgst).

## Зависимости

- Python 3.9+
- [pycryptodome](https://pypi.org/project/pycryptodome/) — используется **только** как примитив AES (шифрование/расшифрование одного 16-байтного блока). Логика всех режимов (ECB, CBC, CFB, OFB, CTR) и padding PKCS#7 реализована самостоятельно.
- OpenSSL CLI — только для тестов совместимости.
- [blake3](https://pypi.org/project/blake3/) — необязательно, только как эталон в тестах BLAKE3 (`pip install blake3`). Все хеш-функции реализованы самостоятельно и внешних зависимостей не имеют.
- `curl`, `unzip`, C-компилятор и `make` — только для статистических тестов NIST STS.

## Сборка / установка

```bash
# 1. Создать и активировать виртуальное окружение
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Установить сам инструмент (регистрирует команду `cryptocore`)
pip install -e .
```

После этого команда `cryptocore` доступна прямо из терминала (в активированном venv).

Без установки пакета инструмент можно запускать и так:

```bash
python3 -m src.cli_parser [аргументы]
```

## Аргументы шифрования

| Аргумент | Описание |
| --- | --- |
| `--algorithm` | Шифр (сейчас — только `aes`) |
| `--mode` | Режим работы: `ecb`, `cbc`, `cfb`, `ofb`, `ctr` |
| `--encrypt` / `--decrypt` | Ровно один из флагов — операция шифрования/расшифрования |
| `--key` | Ключ в виде hex-строки (32 hex-символа = 16 байт для AES-128). **Обязателен при `--decrypt`**; при `--encrypt` необязателен — без него ключ генерируется, см. ниже |
| `--iv` | IV в виде hex-строки (32 hex-символа = 16 байт). **Только при `--decrypt`**, см. ниже |
| `--input` | Путь к входному файлу |
| `--output` | Путь к выходному файлу (опционально — по умолчанию `<input>.enc` / `<input>.dec`) |

## Режимы

| Режим | Схема | Padding | IV |
| --- | --- | --- | --- |
| `ecb` | `C_i = E_k(P_i)` | PKCS#7 | не используется |
| `cbc` | `C_i = E_k(P_i ⊕ C_{i-1})`, `C_0 = IV` | PKCS#7 | 16 байт |
| `cfb` | `C_i = P_i ⊕ E_k(C_{i-1})`, сегмент 128 бит | нет | 16 байт |
| `ofb` | `O_i = E_k(O_{i-1})`, `C_i = P_i ⊕ O_i` | нет | 16 байт |
| `ctr` | `C_i = P_i ⊕ E_k(IV + i)`, счётчик — 128-битное big-endian число | нет | 16 байт |

В потоковых режимах (CFB, OFB, CTR) шифртекст имеет ровно ту же длину, что и открытый текст: неполный последний блок обрабатывается без дополнения.

## Работа с IV

- **Шифрование** (`cbc`, `cfb`, `ofb`, `ctr`): IV генерируется автоматически через CSPRNG проекта (`generate_random_bytes(16)`, см. [CSPRNG](#csprng)) и записывается в начало выходного файла. Формат файла:

  ```
  <16 байт IV><шифртекст>
  ```

  Флаг `--iv` при шифровании **запрещён** — инструмент завершится с ошибкой.
- **Расшифрование:**
  - без `--iv` — первые 16 байт входного файла считаются IV, остаток — шифртекстом (формат, который создаёт сам CryptoCore). Если файл короче 16 байт, выдаётся ошибка;
  - с `--iv <hex>` — весь входной файл считается шифртекстом, а IV берётся из аргумента (например, для файлов, зашифрованных OpenSSL).
- В режиме `ecb` IV не используется: выходной файл не содержит IV, а `--iv` при расшифровании игнорируется с предупреждением.

## Генерация ключа

Если при **шифровании** не указать `--key`, инструмент:

1. генерирует случайный 16-байтный (128-битный) ключ через CSPRNG;
2. сразу выводит его **один раз** в `stdout` с меткой `[INFO] Generated random key:`;
3. шифрует файл этим ключом.

Ключ **не записывается** в выходной файл — сохранить его должен сам пользователь. Без ключа расшифровать файл невозможно.

```bash
$ cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
[INFO] Generated random key: 5f1c0e9a8b7d6c4e3a2f1b0c9d8e7f6a
Шифрование файла 'plaintext.txt' в 'ciphertext.bin' с использованием алгоритма aes в режиме ctr.
IV (записан в начало выходного файла): 3c9e...

# Расшифрование — ключ обязателен
$ cryptocore --algorithm aes --mode ctr --decrypt --key 5f1c0e9a8b7d6c4e3a2f1b0c9d8e7f6a \
    --input ciphertext.bin --output decrypted.txt
```

При **расшифровании** `--key` обязателен: без него инструмент выводит ошибку и завершается с ненулевым кодом.

**Предупреждение о слабом ключе.** Если переданный через `--key` ключ выглядит слабым, в `stderr` выводится `[WARNING]`, но операция выполняется. Слабым считается ключ:
- все байты которого одинаковые (`0000…00`, `ffff…ff`);
- байты которого идут подряд по возрастанию или убыванию (`000102…0f`, `0f0e…00`);
- составленный всего из двух различных байт (`abab…ab`).

Поэтому примеры с ключом `000102030405060708090a0b0c0d0e0f` ниже работают, но печатают такое предупреждение.

## CSPRNG

Модуль [`src/csprng.py`](src/csprng.py) — единственный источник случайности в проекте. Функция `generate_random_bytes(num_bytes: int) -> bytes` используется для генерации ключей и всех IV.

Свойства безопасности:
- Источник — `os.urandom()`, то есть системный CSPRNG операционной системы: `getentropy()`/`getrandom()` в macOS и Linux, `BCryptGenRandom` в Windows. Его состояние регулярно пополняется энтропией из ядра ОС, а выход вычислительно неотличим от случайного и непредсказуем даже при знании предыдущих выходов.
- Модуль `random` (Mersenne Twister) **не используется**: по 624 выходам его состояние восстанавливается полностью, и все дальнейшие значения становятся предсказуемыми.
- Ошибки обрабатываются явно. Если ОС не может выдать случайные байты (`OSError`, `NotImplementedError`) или вернула меньше байт, чем запрошено, выбрасывается `CSPRNGError` с понятным сообщением, а CLI завершается с ошибкой. Шифрование на слабой случайности не выполняется.
- Некорректные аргументы (отрицательная длина, не-`int`) дают `ValueError`/`TypeError`.

## Хеширование: команда `dgst`

Подкоманда `dgst` вычисляет message digest файла. Она отделена от шифрования и не принимает его аргументы.

```bash
cryptocore dgst --algorithm ALGORITHM --input INPUT_FILE [--output FILE]
```

| Аргумент | Описание |
| --- | --- |
| `--algorithm` | Хеш-функция: `sha256`, `sha3-256` или `blake3` |
| `--input` | Путь к входному файлу; `-` — стандартный ввод |
| `--output` | Необязательно: записать результат в файл вместо `stdout` (в том же формате) |

- Вывод — в формате `*sum`-утилит: `HASH_VALUE  INPUT_FILE_PATH` (хеш в нижнем регистре, два пробела, путь), строка заканчивается переводом строки. Если в имени файла есть `\` или перевод строки, они экранируются, а строка начинается с `\`, как в `sha256sum`.
- `--key`, `--iv`, `--mode`, `--encrypt`, `--decrypt` с `dgst` недопустимы: инструмент завершается с ошибкой и ничего не печатает в `stdout`.
- Файл читается в бинарном режиме кусками по 8192 байта, поэтому потребление памяти не зависит от размера файла.
- Ошибки ввода-вывода (нет файла, каталог вместо файла, нет прав, несуществующий каталог для `--output`) выводятся понятным сообщением в `stderr`, код возврата 1. Если `--output` указывает на сам входной файл (в том числе через ссылку), команда отказывается его перезаписывать.

### Примеры

```bash
# Базовое вычисление хеша
$ cryptocore dgst --algorithm sha256 --input document.pdf
5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5  document.pdf

# Запись хеша в файл вместо stdout
$ cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3

# Стандартный ввод
$ echo -n "abc" | cryptocore dgst --algorithm sha256 --input -
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -

# Сверка с системной утилитой (на macOS вместо sha256sum — shasum -a 256)
$ cryptocore dgst --algorithm sha256 --input large_file.iso > my_hash.txt
$ sha256sum large_file.iso > system_hash.txt
$ diff my_hash.txt system_hash.txt   # различий нет

# Проверка целостности по сохранённому хешу
$ cryptocore dgst --algorithm sha256 --input file.bin --output file.sha256
$ sha256sum -c file.sha256
file.bin: OK
```

### Реализованные алгоритмы

Все три алгоритма реализованы с нуля (без `hashlib`) в [`src/hash/`](src/hash/), с общим интерфейсом `update()` / `digest()` / `hexdigest()` ([`common.py`](src/hash/common.py)). `digest()` не портит состояние: после него можно продолжать `update()`.

| Алгоритм | Стандарт | Конструкция | Блок | Выход | Раундов |
| --- | --- | --- | --- | --- | --- |
| `sha256` | NIST FIPS 180-4 | Merkle–Damgård, функция сжатия Дэвиса–Мейера | 512 бит | 256 бит | 64 |
| `sha3-256` | NIST FIPS 202 | губка Keccak-f[1600], rate 1088 бит, capacity 512 бит | 1088 бит | 256 бит | 24 |
| `blake3` | спецификация BLAKE3 (2020) | дерево Меркла из чанков по 1024 байта, сжатие на основе ChaCha | 512 бит | 256 бит | 7 |

**SHA-256** ([`sha256.py`](src/hash/sha256.py)). Сообщение дополняется битом `1`, нулями до 448 mod 512 и 64-битной длиной в битах (big-endian), затем обрабатывается блоками по 512 бит. Начальные значения `H0` — первые 32 бита дробных частей квадратных корней первых 8 простых чисел; раундовые константы `K` — кубических корней первых 64 простых. Расписание сообщения расширяет 16 слов до 64, в каждом раунде используются функции `Ch`, `Maj`, `Σ0`, `Σ1`. Длина сообщения ограничена 2^64 − 1 бит, превышение даёт `ValueError`.

**SHA3-256** ([`sha3_256.py`](src/hash/sha3_256.py)). Состояние 5×5 дорожек по 64 бита. Блоки по 136 байт (rate) впитываются через XOR, после каждого — перестановка Keccak-f[1600] из 24 раундов θ, ρ, π, χ, ι. Смещения ρ и константы ι вычисляются по формулам FIPS 202 (LFSR), а не задаются таблицей. Padding — `pad10*1` с доменным суффиксом SHA-3 `01` (первый байт `0x06`, последний бит `0x80`). Выжимается 256 бит.

**BLAKE3** ([`blake3.py`](src/hash/blake3.py)). Третий алгоритм, сверх требований ТЗ. Вход режется на чанки по 1024 байта, чанк — на блоки по 64 байта; функция сжатия — 7 раундов функции `G` (ARX) над матрицей 4×4 с перестановкой слов сообщения между раундами. Значения цепочки чанков объединяются в бинарное дерево Меркла через стек, флаги `CHUNK_START`, `CHUNK_END`, `PARENT`, `ROOT` разделяют домены.

### Свойства безопасности

| | SHA-256 | SHA3-256 | BLAKE3 |
| --- | --- | --- | --- |
| Стойкость к коллизиям | 128 бит | 128 бит | 128 бит |
| Стойкость к нахождению прообраза | 256 бит | 256 бит | 128 бит (заявленная авторами) |
| Атака удлинения сообщения (length extension) | **уязвим** | стойкий | стойкий |
| Известные практические атаки на полный алгоритм | нет | нет | нет |

- Стойкость к коллизиям 256-битного хеша ограничена парадоксом дней рождения: ≈ 2^128 операций. Авторы BLAKE3 заявляют 128-битную стойкость для всех целей, включая прообраз: у алгоритма всего 7 раундов и меньший запас прочности, зато он заметно быстрее.
- **SHA-256 уязвим к атаке удлинения сообщения**: по `H(m)` и длине `m` можно вычислить `H(m ‖ padding ‖ x)`, не зная `m`. Поэтому конструкция `H(key ‖ message)` как MAC с SHA-256 небезопасна — нужен HMAC. У SHA3-256 выход не раскрывает внутреннее состояние (capacity 512 бит не выдаётся наружу), у BLAKE3 корневой узел помечен флагом `ROOT`, поэтому оба к этой атаке стойки.
- Хеш обеспечивает только **целостность**, но не подлинность: злоумышленник, подменивший файл, может пересчитать и хеш. Для подлинности нужен ключ (MAC — следующий спринт).
- Реализации учебные и написаны на чистом Python: они медленные (≈ 0,4–0,7 МБ/с, см. [TESTING.md](TESTING.md#производительность-test-6)) и не защищены от атак по сторонним каналам. Для хеширования открытых данных это не важно.

## Примеры использования

```bash
# Шифрование в CBC (IV генерируется и печатается, а также записывается в начало файла)
cryptocore --algorithm aes --mode cbc --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt --output ciphertext.bin

# Расшифрование: IV читается из первых 16 байт ciphertext.bin
cryptocore --algorithm aes --mode cbc --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input ciphertext.bin --output decrypted.txt

# Расшифрование с явным IV (файл содержит только шифртекст, без IV)
cryptocore --algorithm aes --mode ctr --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --iv AABBCCDDEEFF00112233445566778899 \
    --input openssl_cipher.bin --output decrypted.txt

# ECB (как в спринте 1, без IV)
cryptocore --algorithm aes --mode ecb --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt --output ciphertext.bin
```

## Проверка полного цикла (encrypt → decrypt)

```bash
for MODE in ecb cbc cfb ofb ctr; do
    cryptocore --algorithm aes --mode $MODE --encrypt \
        --key 000102030405060708090a0b0c0d0e0f \
        --input original_file.txt --output ciphertext.bin
    cryptocore --algorithm aes --mode $MODE --decrypt \
        --key 000102030405060708090a0b0c0d0e0f \
        --input ciphertext.bin --output decrypted_file.txt
    diff original_file.txt decrypted_file.txt && echo "$MODE: OK, файлы идентичны"
done
```

## Тесты

```bash
python3 -m unittest discover -s tests
```

- `tests/test_ecb.py` — режим ECB и PKCS#7;
- `tests/test_modes.py` — CBC/CFB/OFB/CTR: официальные тестовые векторы NIST SP 800-38A, полный цикл на данных разной длины (0, 1, 15, 16, 17, … байт), сверка с эталонной реализацией, переполнение счётчика CTR;
- `tests/test_cli.py` — CLI: полный цикл через файлы, формат `<IV><шифртекст>`, запрет `--iv` при шифровании, слишком короткий файл, генерация ключа без `--key` и последующее расшифрование, обязательный `--key` при расшифровании, предупреждение о слабом ключе, а также совместимость с OpenSSL в обе стороны (пропускается, если `openssl` не установлен);
- `tests/test_csprng.py` — CSPRNG: уникальность 1000 ключей по 16 байт, средний вес Хэмминга (~50% единичных битов), равномерность байтов (хи-квадрат), обработка ошибок ОС и некорректных аргументов, отсутствие модуля `random`, распознавание слабых ключей;
- `tests/test_hash.py` — хеш-функции: векторы NIST (FIPS 180-4, FIPS 202) и официальные векторы BLAKE3, сверка с эталоном на всех длинах вокруг границ блоков, padding SHA-256, обработка по частям, постоянная память, лавинный эффект;
- `tests/test_dgst_cli.py` — команда `dgst`: формат вывода, побайтовое совпадение с `sha256sum`/`shasum`, совместимость с системными утилитами, пустой файл, `stdin`, `--output`, запрет аргументов шифрования, ошибки ввода-вывода. Тест на файле больше 1 ГБ включается переменной `CRYPTOCORE_LARGE_TEST=1` (≈ 45 минут).

Сравнение скорости с системными утилитами: `python3 -m tests.bench_hash`. Подробности — в [TESTING.md](TESTING.md).

## Статистические тесты NIST STS

CSPRNG проверен официальным набором [NIST Statistical Test Suite 2.1.2](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software): все 15 тестов на 100 последовательностях по 1 000 000 бит. Результат — **все 15 тестов пройдены, 186 из 188 подтестов**. Два отказа — единичные шаблоны NonOverlappingTemplate (95/100 при пороге 96/100); это статистически ожидаемо, контрольный прогон на других данных дал 188/188. Подробности и таблица результатов — в [TESTING.md](TESTING.md), полный отчёт — в [docs/nist_sts/finalAnalysisReport.txt](docs/nist_sts/finalAnalysisReport.txt).

Повторить прогон одной командой (нужны `curl`, `unzip`, C-компилятор и `make`; занимает ~3–5 минут):

```bash
bash tests/run_nist_sts.sh
```

Скрипт скачивает и собирает NIST STS в папку `nist_sts/`, генерирует 12,5 МБ данных через `generate_random_bytes`, запускает все 15 тестов и сохраняет отчёт в `docs/nist_sts/finalAnalysisReport.txt`. Только сгенерировать данные можно так:

```bash
python3 -m tests.generate_nist_data nist_test_data.bin 12500000
```

## Тесты совместимости с OpenSSL

Готовый сценарий проверяет все четыре режима в обе стороны (CryptoCore → OpenSSL и OpenSSL → CryptoCore) на файле длиной 1000 байт (не кратной 16):

```bash
bash tests/openssl_compat.sh
# или с установленной командой:
CRYPTOCORE=cryptocore bash tests/openssl_compat.sh
```

Ожидаемый вывод:

```
[OK]   cbc: CryptoCore -> OpenSSL
[OK]   cbc: OpenSSL -> CryptoCore
[OK]   cfb: CryptoCore -> OpenSSL
[OK]   cfb: OpenSSL -> CryptoCore
[OK]   ofb: CryptoCore -> OpenSSL
[OK]   ofb: OpenSSL -> CryptoCore
[OK]   ctr: CryptoCore -> OpenSSL
[OK]   ctr: OpenSSL -> CryptoCore
```

Те же проверки вручную (подставьте `cbc`, `cfb`, `ofb` или `ctr` вместо `MODE`):

```bash
MODE=cbc
KEY=2b7e151628aed2a6abf7158809cf4f3c

# 1. Шифрование CryptoCore -> расшифрование OpenSSL
cryptocore --algorithm aes --mode $MODE --encrypt --key $KEY --input plain.txt --output cipher.bin
dd if=cipher.bin of=iv.bin bs=16 count=1                # первые 16 байт — IV
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1    # остальное — шифртекст
openssl enc -aes-128-$MODE -d -K $KEY -iv $(xxd -p iv.bin | tr -d '\n') \
    -in ciphertext_only.bin -out decrypted.txt
diff plain.txt decrypted.txt && echo OK

# 2. Шифрование OpenSSL -> расшифрование CryptoCore
openssl enc -aes-128-$MODE -K $KEY -iv AABBCCDDEEFF00112233445566778899 \
    -in plain.txt -out openssl_cipher.bin
cryptocore --algorithm aes --mode $MODE --decrypt --key $KEY \
    --iv AABBCCDDEEFF00112233445566778899 \
    --input openssl_cipher.bin --output decrypted.txt
diff plain.txt decrypted.txt && echo OK
```

`openssl enc -aes-128-cfb` использует CFB с сегментом 128 бит, а `-aes-128-ctr` — 128-битный big-endian счётчик, поэтому результаты совпадают с CryptoCore байт в байт.

## Структура проекта

```
CryptoCore/
├── src/
│   ├── cli_parser.py     # разбор и валидация аргументов, ключ/IV, выбор режима, команда dgst
│   ├── csprng.py         # CSPRNG: generate_random_bytes (os.urandom)
│   ├── file_io.py        # чтение/запись файлов (в т. ч. по частям), обработка ошибок ввода-вывода
│   ├── hash/
│   │   ├── common.py     # общий интерфейс хеш-функций
│   │   ├── sha256.py     # SHA-256 (FIPS 180-4)
│   │   ├── sha3_256.py   # SHA3-256 (FIPS 202, Keccak)
│   │   └── blake3.py     # BLAKE3
│   └── modes/
│       ├── common.py     # примитив AES, PKCS#7, разбиение на блоки, XOR
│       ├── ecb.py        # ECB (+ PKCS#7)
│       ├── cbc.py        # CBC (+ PKCS#7)
│       ├── cfb.py        # CFB-128 (потоковый)
│       ├── ofb.py        # OFB (потоковый)
│       └── ctr.py        # CTR (потоковый)
├── tests/
│   ├── test_ecb.py
│   ├── test_modes.py
│   ├── test_cli.py
│   ├── test_csprng.py
│   ├── test_hash.py
│   ├── test_dgst_cli.py
│   ├── bench_hash.py           # TEST-6: скорость против системных утилит
│   ├── openssl_compat.sh
│   ├── generate_nist_data.py   # данные для NIST STS
│   └── run_nist_sts.sh         # полный прогон NIST STS
├── docs/nist_sts/finalAnalysisReport.txt
├── requirements.txt
├── setup.py
├── README.md
└── TESTING.md
```
