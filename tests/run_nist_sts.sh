# Прогон NIST Statistical Test Suite 2.1.2 (все 15 тестов) на выходе CSPRNG проекта (TEST-3).
# Запуск из корня проекта:  bash tests/run_nist_sts.sh
# Требуются: curl, unzip, C-компилятор (cc/gcc), make. Прогон занимает ~3-5 минут.
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
STS_URL="https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip"
WORK="nist_sts"                    # рабочая папка (в .gitignore)
STS_DIR="$WORK/sts-2.1.2/sts-2.1.2"
SEQ_LEN=1000000                    # длина одной последовательности, бит
NUM_SEQ=100                        # число последовательностей
# assess читает путь через scanf("%s") и обрывает его на пробеле, поэтому данные кладём
# внутрь папки STS и передаём относительный путь без пробелов
DATA_NAME="data/nist_test_data.bin"

mkdir -p "$WORK"

# 1. Скачать и собрать NIST STS
if [ ! -x "$STS_DIR/assess" ]; then
    echo "==> Скачивание и сборка NIST STS"
    curl -sSL -o "$WORK/sts.zip" "$STS_URL"
    unzip -q -o "$WORK/sts.zip" -d "$WORK"
    make -C "$STS_DIR" CC=cc GCCFLAGS="-c -O3 -w" > /dev/null
fi

# 2. Сгенерировать данные: 100 * 1 000 000 бит = 12.5 МБ из generate_random_bytes
echo "==> Генерация тестовых данных"
"$PYTHON" -m tests.generate_nist_data "$STS_DIR/$DATA_NAME" $((SEQ_LEN * NUM_SEQ / 8))

# 3. Запустить assess, отвечая на интерактивные вопросы:
#    0 — читать из файла; путь к файлу; 1 — выполнить все 15 тестов;
#    0 — параметры по умолчанию; 100 — число последовательностей; 1 — двоичный формат
echo "==> Запуск всех 15 тестов (несколько минут)"
REPORT="$STS_DIR/experiments/AlgorithmTesting/finalAnalysisReport.txt"
rm -f "$REPORT"
# код возврата assess ненадёжен, поэтому успех определяем по появлению отчёта
(cd "$STS_DIR" && printf '0\n%s\n1\n0\n%s\n1\n' "$DATA_NAME" "$NUM_SEQ" | ./assess "$SEQ_LEN" > /dev/null) || true
if [ ! -s "$REPORT" ]; then
    echo "Ошибка: NIST STS не сформировал отчёт $REPORT" >&2
    exit 1
fi
mkdir -p docs/nist_sts
sed "s#<.*nist_test_data.bin>#<nist_test_data.bin>#" "$REPORT" > docs/nist_sts/finalAnalysisReport.txt
echo "==> Отчёт: docs/nist_sts/finalAnalysisReport.txt"

# 4. Проваленные подтесты помечены в отчёте звёздочкой '*'
FAILED=$(grep -c '\*' docs/nist_sts/finalAnalysisReport.txt || true)
TOTAL=$(grep -cE '^ *([0-9]+ +){10}[0-9.]+' docs/nist_sts/finalAnalysisReport.txt || true)
echo "==> Подтестов: $TOTAL, провалено: $FAILED"
