#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse
import os
import secrets
from typing import List, Tuple

# ====================== КОНСТАНТЫ AES ======================

# S-box (SubBytes) — нелинейная замена байтов при шифровании
S_BOX: List[int] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-box (для расшифрования)
INV_S_BOX: List[int] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

RCON: List[int] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
BLOCK_SIZE = 16

# ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======================

def generate_key(key_size: int = 128) -> str:
    if key_size not in (128, 192, 256):
        raise ValueError("Размер ключа должен быть 128, 192 или 256 бит")
    return secrets.token_bytes(key_size // 8).hex()


def xtime(x: int) -> int:
    return ((x << 1) ^ 0x1B) & 0xFF if (x & 0x80) else (x << 1)


def mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p & 0xFF


def bytes_to_state(data: bytes) -> List[List[int]]:
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state


def state_to_bytes(state: List[List[int]]) -> bytes:
    return bytes(state[i % 4][i // 4] for i in range(16))


# ====================== ОСНОВНЫЕ ПРЕОБРАЗОВАНИЯ ======================

def sub_bytes(state: List[List[int]], inv: bool = False) -> None:
    box = INV_S_BOX if inv else S_BOX
    for i in range(4):
        for j in range(4):
            state[i][j] = box[state[i][j]]


def shift_rows(state: List[List[int]], inv: bool = False) -> None:
    if not inv:
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
    else:
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]


def mix_columns(state: List[List[int]], inv: bool = False) -> None:
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        if not inv:
            state[0][i] = mul(col[0], 2) ^ mul(col[1], 3) ^ col[2] ^ col[3]
            state[1][i] = col[0] ^ mul(col[1], 2) ^ mul(col[2], 3) ^ col[3]
            state[2][i] = col[0] ^ col[1] ^ mul(col[2], 2) ^ mul(col[3], 3)
            state[3][i] = mul(col[0], 3) ^ col[1] ^ col[2] ^ mul(col[3], 2)
        else:
            state[0][i] = mul(col[0], 0x0E) ^ mul(col[1], 0x0B) ^ mul(col[2], 0x0D) ^ mul(col[3], 0x09)
            state[1][i] = mul(col[0], 0x09) ^ mul(col[1], 0x0E) ^ mul(col[2], 0x0B) ^ mul(col[3], 0x0D)
            state[2][i] = mul(col[0], 0x0D) ^ mul(col[1], 0x09) ^ mul(col[2], 0x0E) ^ mul(col[3], 0x0B)
            state[3][i] = mul(col[0], 0x0B) ^ mul(col[1], 0x0D) ^ mul(col[2], 0x09) ^ mul(col[3], 0x0E)


def add_round_key(state: List[List[int]], round_key: List[int]) -> None:
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i + 4 * j]


# ====================== KEY EXPANSION ======================

def key_expansion(key: bytes) -> Tuple[List[List[int]], int]:
    """Возвращает список раундовых ключей и количество раундов nr"""
    key_len = len(key)
    if key_len not in (16, 24, 32):
        raise ValueError("Ключ должен быть 16, 24 или 32 байта (AES-128/192/256)")

    nk = key_len // 4
    nr = nk + 6
    nb = 4

    w = [0] * (nb * (nr + 1))
    for i in range(nk):
        w[i] = int.from_bytes(key[4*i:4*i+4], "big")

    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            temp = ((S_BOX[(temp >> 24) & 0xFF] << 24) |

(S_BOX[(temp >> 16) & 0xFF] << 16) |
                    (S_BOX[(temp >> 8)  & 0xFF] << 8)  |
                    S_BOX[temp & 0xFF])
            temp ^= RCON[i // nk] << 24
        elif nk > 6 and i % nk == 4:
            temp = ((S_BOX[(temp >> 24) & 0xFF] << 24) |
                    (S_BOX[(temp >> 16) & 0xFF] << 16) |
                    (S_BOX[(temp >> 8)  & 0xFF] << 8)  |
                    S_BOX[temp & 0xFF])

        w[i] = w[i - nk] ^ temp

    round_keys = []
    for r in range(nr + 1):
        rk = []
        for j in range(nb):
            word = w[r * nb + j]
            rk.extend([(word >> 24) & 0xFF, (word >> 16) & 0xFF,
                       (word >> 8) & 0xFF, word & 0xFF])
        round_keys.append(rk)

    return round_keys, nr


# ====================== ШИФРОВАНИЕ / РАСШИФРОВАНИЕ БЛОКА ======================

def aes_encrypt_block(block: bytes, round_keys: List[List[int]], nr: int) -> bytes:
    """Добавлена проверка длины блока, чтобы не было index out of range."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Блок для шифрования должен быть ровно 16 байт (получено {len(block)})")
    state = bytes_to_state(block)
    add_round_key(state, round_keys[0])
    for rnd in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[nr])
    return state_to_bytes(state)


def aes_decrypt_block(block: bytes, round_keys: List[List[int]], nr: int) -> bytes:
    #проверка длины блока
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Блок для расшифрования должен быть ровно 16 байт (получено {len(block)} байт). "
                         "Файл, скорее всего, повреждён или зашифрован в другом режиме.")
    state = bytes_to_state(block)
    add_round_key(state, round_keys[nr])
    for rnd in range(nr-1, 0, -1):
        shift_rows(state, inv=True)
        sub_bytes(state, inv=True)
        add_round_key(state, round_keys[rnd])
        mix_columns(state, inv=True)
    shift_rows(state, inv=True)
    sub_bytes(state, inv=True)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)


# ====================== ДОПОЛНЕНИЕ БЛОКОВ ======================

def pkcs7_pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Удаляет PKCS7 padding с понятной ошибкой."""
    if len(data) == 0:
        raise ValueError("Пустой файл после расшифрования")
    
    padding_len = data[-1]
    
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError(
            f"Неверный PKCS7 padding (значение {padding_len}).\n"
            "Скорее всего, неправильный ключ или файл повреждён."
        )
    
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError(
            f"Неверный PKCS7 padding.\n"
            "Возможные причины:\n"
            "  • Неправильный ключ\n"
            "  • Файл не был зашифрован в режиме " + "CBC" + "\n"
            "  • Повреждён .enc файл"
        )
    
    return data[:-padding_len]


# ====================== РЕЖИМЫ ШИФРОВАНИЯ ======================

def encrypt_ecb(plaintext: bytes, round_keys: List[List[int]], nr: int) -> bytes:
    plaintext = pkcs7_pad(plaintext)
    ciphertext = b""
    for i in range(0, len(plaintext), BLOCK_SIZE):
        ciphertext += aes_encrypt_block(plaintext[i:i+BLOCK_SIZE], round_keys, nr)
    return ciphertext


def decrypt_ecb(ciphertext: bytes, round_keys: List[List[int]], nr: int) -> bytes:
    plaintext = b""
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        plaintext += aes_decrypt_block(ciphertext[i:i+BLOCK_SIZE], round_keys, nr)
    return pkcs7_unpad(plaintext)


def encrypt_cbc(plaintext: bytes, round_keys: List[List[int]], nr: int, iv: bytes) -> bytes:
    """CBC — Cipher Block Chaining. Каждый блок XORится с предыдущим шифртекстом."""
    plaintext = pkcs7_pad(plaintext)
    ciphertext = iv[:]                      # IV сохраняется в начале шифртекста
    prev = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]
        block = bytes(a ^ b for a, b in zip(block, prev))
        encrypted = aes_encrypt_block(block, round_keys, nr)
        ciphertext += encrypted
        prev = encrypted

    return ciphertext


def decrypt_cbc(ciphertext: bytes, round_keys: List[List[int]], nr: int) -> bytes:
    """Расшифрование CBC. Первый блок — IV."""
    if len(ciphertext) < BLOCK_SIZE:
        raise ValueError("Слишком короткий шифртекст для CBC")
    
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext = ciphertext[BLOCK_SIZE:]
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        decrypted = aes_decrypt_block(block, round_keys, nr)
        plain_block = bytes(a ^ b for a, b in zip(decrypted, prev))
        plaintext += plain_block
        prev = block
    return pkcs7_unpad(plaintext)

def encrypt_ctr(plaintext: bytes, round_keys: List[List[int]], nr: int, nonce: bytes) -> bytes:
    """CTR — исправлена длина nonce (теперь 8 байт и в шифровании, и в расшифровании)."""
    ciphertext = nonce[:]                   # 8 байт nonce в начале
    counter = 0

    for i in range(0, len(plaintext), BLOCK_SIZE):
        counter_block = nonce + counter.to_bytes(8, "big")
        keystream = aes_encrypt_block(counter_block, round_keys, nr)
        block = plaintext[i:i + BLOCK_SIZE]
        encrypted = bytes(a ^ b for a, b in zip(block, keystream))
        ciphertext += encrypted
        counter += 1

    return ciphertext


def decrypt_ctr(ciphertext: bytes, round_keys: List[List[int]], nr: int) -> bytes:
    """CTR — исправлено взятие nonce (теперь 8 байт)."""
    if len(ciphertext) < 8:
        raise ValueError("Слишком короткий шифртекст для CTR")
    
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    plaintext = b""
    counter = 0

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        counter_block = nonce + counter.to_bytes(8, "big")
        keystream = aes_encrypt_block(counter_block, round_keys, nr)
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = bytes(a ^ b for a, b in zip(block, keystream))
        plaintext += decrypted
        counter += 1

    return plaintext

# ====================== MAIN ======================

def main():
    parser = argparse.ArgumentParser(
        description="AES-128/192/256 реализация с нуля. Режимы: ECB, CBC, CTR"
    )
    
    parser.add_argument("-e", "--encrypt", action="store_true", help="Зашифровать")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Расшифровать")
    parser.add_argument("--gen-key", type=int, choices=[128, 192, 256],
                        help="Сгенерировать случайный ключ")
    
    parser.add_argument("-f", "--file", required=False, help="Входной файл")
    parser.add_argument("-k", "--key", help="Ключ в HEX")
    parser.add_argument("-m", "--mode", default="ECB", choices=["ECB", "CBC", "CTR"],
                        help="Режим шифрования (ECB | CBC | CTR)")
    parser.add_argument("-o", "--output", help="Выходной файл")

    args = parser.parse_args()

    # Генерация ключа
    if args.gen_key:
        key_hex = generate_key(args.gen_key)
        print(f"✅ Сгенерирован ключ AES-{args.gen_key}:")
        print(key_hex)
        print(f"\nПример: python {sys.argv[0]} -e -f file.txt -k {key_hex} -m CBC")
        sys.exit(0)

    if not args.encrypt and not args.decrypt:
        print("Укажите --encrypt или --decrypt")
        parser.print_help()
        sys.exit(1)

    if args.encrypt == args.decrypt:
        print("Нельзя указывать одновременно --encrypt и --decrypt")
        sys.exit(1)

    if not args.file:
        print("Укажите входной файл (--file)")
        sys.exit(1)

    if not args.key:
        print("Укажите ключ (--key) или используйте --gen-key")
        sys.exit(1)

    # Чтение ключа
    try:
        key = bytes.fromhex(args.key)
    except Exception:
        print("Ключ должен быть в HEX формате")
        sys.exit(1)

    round_keys, nr = key_expansion(key)
    aes_bits = len(key) * 8
    print(f"✅ AES-{aes_bits} ({nr} раундов), режим: {args.mode}")

    with open(args.file, "rb") as f:
        data = f.read()

# ====================== ВЫПОЛНЕНИЕ ШИФРОВАНИЯ / РАСШИФРОВАНИЯ ======================
    try:
        if args.encrypt:
            if args.mode == "ECB":
                result = encrypt_ecb(data, round_keys, nr)
            elif args.mode == "CBC":
                iv = secrets.token_bytes(BLOCK_SIZE)
                result = encrypt_cbc(data, round_keys, nr, iv)
            elif args.mode == "CTR":
                nonce = secrets.token_bytes(8)   # 64-битный nonce
                result = encrypt_ctr(data, round_keys, nr, nonce)
            else:
                print(f"Режим {args.mode} не поддерживается")
                sys.exit(1)
        else:  # decrypt
            if args.mode == "ECB":
                result = decrypt_ecb(data, round_keys, nr)
            elif args.mode == "CBC":
                result = decrypt_cbc(data, round_keys, nr)
            elif args.mode == "CTR":
                result = decrypt_ctr(data, round_keys, nr)
            else:
                print(f"Режим {args.mode} не поддерживается")
                sys.exit(1)
    except Exception as e:
        print(f"Ошибка при {'шифровании' if args.encrypt else 'расшифровании'}: {e}")
        sys.exit(1)

    # ====================== СОХРАНЕНИЕ РЕЗУЛЬТАТА ======================
    if args.output:
        out_file = args.output
    else:
        base, orig_ext = os.path.splitext(args.file)
        if args.encrypt:
            out_file = base + ".enc"
        else:
            # При расшифровании стараемся восстановить оригинальное имя
            if orig_ext.lower() == ".enc":
                out_file = base
            else:
                out_file = base + ".dec"

    with open(out_file, "wb") as f:
        f.write(result)

    action = "зашифрован" if args.encrypt else "расшифрован"
    print(f"✅ Файл успешно {action} в режиме {args.mode}!")
    print(f"Результат сохранён в: {out_file}")

    if not args.encrypt:
        print(f"   Файл можно открыть: {out_file}")


if __name__ == "__main__":
    main()