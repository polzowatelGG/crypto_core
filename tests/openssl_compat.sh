# Тесты совместимости CryptoCore <-> OpenSSL для режимов CBC, CFB, OFB, CTR (TEST-2, TEST-3).
# Запуск из корня проекта:  bash tests/openssl_compat.sh
set -euo pipefail

cd "$(dirname "$0")/.."
KEY=2b7e151628aed2a6abf7158809cf4f3c  # ключ из NIST SP 800-38A (не "слабый")
IV=aabbccddeeff00112233445566778899
CRYPTOCORE="${CRYPTOCORE:-python3 -m src.cli_parser}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# длина 1000 байт — не кратна 16, проверяет неполный последний блок
head -c 1000 /dev/urandom > "$WORK/plain.bin"

fail=0
for MODE in cbc cfb ofb ctr; do
    # 1. CryptoCore шифрует -> OpenSSL расшифровывает
    $CRYPTOCORE --algorithm aes --mode $MODE --encrypt --key $KEY \
        --input "$WORK/plain.bin" --output "$WORK/cipher.bin" > /dev/null
    dd if="$WORK/cipher.bin" of="$WORK/iv.bin" bs=16 count=1 status=none
    dd if="$WORK/cipher.bin" of="$WORK/ciphertext_only.bin" bs=16 skip=1 status=none
    openssl enc -aes-128-$MODE -d -K $KEY -iv "$(xxd -p "$WORK/iv.bin" | tr -d '\n')" \
        -in "$WORK/ciphertext_only.bin" -out "$WORK/dec_openssl.bin"
    if cmp -s "$WORK/plain.bin" "$WORK/dec_openssl.bin"; then
        echo "[OK]   $MODE: CryptoCore -> OpenSSL"
    else
        echo "[FAIL] $MODE: CryptoCore -> OpenSSL"; fail=1
    fi

    # 2. OpenSSL шифрует -> CryptoCore расшифровывает
    openssl enc -aes-128-$MODE -K $KEY -iv $IV \
        -in "$WORK/plain.bin" -out "$WORK/openssl_cipher.bin"
    $CRYPTOCORE --algorithm aes --mode $MODE --decrypt --key $KEY --iv $IV \
        --input "$WORK/openssl_cipher.bin" --output "$WORK/dec_cryptocore.bin" > /dev/null
    if cmp -s "$WORK/plain.bin" "$WORK/dec_cryptocore.bin"; then
        echo "[OK]   $MODE: OpenSSL -> CryptoCore"
    else
        echo "[FAIL] $MODE: OpenSSL -> CryptoCore"; fail=1
    fi
done

exit $fail
