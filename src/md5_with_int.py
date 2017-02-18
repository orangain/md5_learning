from functools import reduce
from math import sin
from struct import iter_unpack, pack


# bytesをwords（32bits以内のintのlist）に変換
def bytes_to_words(input_bytes):
    assert len(input_bytes) % 4 == 0

    # <I は リトルエンディアンのunsigned int (4bytes)
    words = [w[0] for w in iter_unpack('<I', input_bytes)]
    return words


# wordsをbytesに変換
def words_to_bytes(words):
    # <I は リトルエンディアンのunsigned int (4bytes)
    return b''.join((pack('<I', w) for w in words))


# 任意のbit数のintをword（32bits）に切り捨てる
def WORD(n):
    return n & 0xFFFFFFFF


# wordの範囲内のNOT
def NOT(n):
    return WORD(~n)


# wordの範囲内の加算（複数引数可）
def ADD(*args):
    return reduce(lambda x, y: WORD(x + y), args)


# wordの範囲内での左ローテート
def L_ROTATE(n, num_bits):
    for _ in range(num_bits):
        n = ((n & 0x80000000) >> 31) | WORD(n << 1)
    return n


# 補助関数の定義
def F(X, Y, Z):
    return X & Y | NOT(X) & Z


def G(X, Y, Z):
    return X & Z | Y & NOT(Z)


def H(X, Y, Z):
    return X ^ Y ^ Z


def I(X, Y, Z):
    return Y ^ (X | NOT(Z))


# テーブルT
T = {}
for i in range(1, 64 + 1):
    T[i] = WORD(int(4294967296 * abs(sin(i))))


# ステップ1. メッセージの拡張
def add_padding(input_bytes):
    num_bits = len(input_bytes) * 8
    mod = num_bits % 512
    if mod >= 448:
        num_padding_bits = 448 + 512 - mod
    else:
        num_padding_bits = 448 - mod

    # ここで入力はbytes単位 = 8bits単位であると仮定している。
    # Pythonでbytes単位でない入力を扱うことはないと思われるので良いかと。
    assert num_padding_bits % 8 == 0
    num_padding_bytes = num_padding_bits // 8

    # 先頭だけ1のビットを立て、残りは0とする
    # 0x80 == 0b10000000
    return input_bytes + b'\x80' + b'\x00' * (num_padding_bytes - 1)


# ステップ2. メッセージに長さ付加
def add_length(padded_words, num_bits):
    lower_word = WORD(num_bits)
    higher_word = WORD(num_bits >> 32)
    return padded_words + [lower_word, higher_word]


# ステップ4. 算出処理のループ1回分の処理
def calculate_MD5(X, A, B, C, D):
    assert len(X) == 16

    def round1(a, b, c, d, k, s, i):
        return ADD(b, L_ROTATE(ADD(a, F(b, c, d), X[k], T[i]), s))

    def round2(a, b, c, d, k, s, i):
        return ADD(b, L_ROTATE(ADD(a, G(b, c, d), X[k], T[i]), s))

    def round3(a, b, c, d, k, s, i):
        return ADD(b, L_ROTATE(ADD(a, H(b, c, d), X[k], T[i]), s))

    def round4(a, b, c, d, k, s, i):
        return ADD(b, L_ROTATE(ADD(a, I(b, c, d), X[k], T[i]), s))

    AA = A
    BB = B
    CC = C
    DD = D

    A = round1(A, B, C, D,  0,  7,  1)
    D = round1(D, A, B, C,  1, 12,  2)
    C = round1(C, D, A, B,  2, 17,  3)
    B = round1(B, C, D, A,  3, 22,  4)
    A = round1(A, B, C, D,  4,  7,  5)
    D = round1(D, A, B, C,  5, 12,  6)
    C = round1(C, D, A, B,  6, 17,  7)
    B = round1(B, C, D, A,  7, 22,  8)
    A = round1(A, B, C, D,  8,  7,  9)
    D = round1(D, A, B, C,  9, 12, 10)
    C = round1(C, D, A, B, 10, 17, 11)
    B = round1(B, C, D, A, 11, 22, 12)
    A = round1(A, B, C, D, 12,  7, 13)
    D = round1(D, A, B, C, 13, 12, 14)
    C = round1(C, D, A, B, 14, 17, 15)
    B = round1(B, C, D, A, 15, 22, 16)

    A = round2(A, B, C, D,  1,  5, 17)
    D = round2(D, A, B, C,  6,  9, 18)
    C = round2(C, D, A, B, 11, 14, 19)
    B = round2(B, C, D, A,  0, 20, 20)
    A = round2(A, B, C, D,  5,  5, 21)
    D = round2(D, A, B, C, 10,  9, 22)
    C = round2(C, D, A, B, 15, 14, 23)
    B = round2(B, C, D, A,  4, 20, 24)
    A = round2(A, B, C, D,  9,  5, 25)
    D = round2(D, A, B, C, 14,  9, 26)
    C = round2(C, D, A, B,  3, 14, 27)
    B = round2(B, C, D, A,  8, 20, 28)
    A = round2(A, B, C, D, 13,  5, 29)
    D = round2(D, A, B, C,  2,  9, 30)
    C = round2(C, D, A, B,  7, 14, 31)
    B = round2(B, C, D, A, 12, 20, 32)

    A = round3(A, B, C, D,  5,  4, 33)
    D = round3(D, A, B, C,  8, 11, 34)
    C = round3(C, D, A, B, 11, 16, 35)
    B = round3(B, C, D, A, 14, 23, 36)
    A = round3(A, B, C, D,  1,  4, 37)
    D = round3(D, A, B, C,  4, 11, 38)
    C = round3(C, D, A, B,  7, 16, 39)
    B = round3(B, C, D, A, 10, 23, 40)
    A = round3(A, B, C, D, 13,  4, 41)
    D = round3(D, A, B, C,  0, 11, 42)
    C = round3(C, D, A, B,  3, 16, 43)
    B = round3(B, C, D, A,  6, 23, 44)
    A = round3(A, B, C, D,  9,  4, 45)
    D = round3(D, A, B, C, 12, 11, 46)
    C = round3(C, D, A, B, 15, 16, 47)
    B = round3(B, C, D, A,  2, 23, 48)

    A = round4(A, B, C, D,  0,  6, 49)
    D = round4(D, A, B, C,  7, 10, 50)
    C = round4(C, D, A, B, 14, 15, 51)
    B = round4(B, C, D, A,  5, 21, 52)
    A = round4(A, B, C, D, 12,  6, 53)
    D = round4(D, A, B, C,  3, 10, 54)
    C = round4(C, D, A, B, 10, 15, 55)
    B = round4(B, C, D, A,  1, 21, 56)
    A = round4(A, B, C, D,  8,  6, 57)
    D = round4(D, A, B, C, 15, 10, 58)
    C = round4(C, D, A, B,  6, 15, 59)
    B = round4(B, C, D, A, 13, 21, 60)
    A = round4(A, B, C, D,  4,  6, 61)
    D = round4(D, A, B, C, 11, 10, 62)
    C = round4(C, D, A, B,  2, 15, 63)
    B = round4(B, C, D, A,  9, 21, 64)

    A = ADD(A, AA)
    B = ADD(B, BB)
    C = ADD(C, CC)
    D = ADD(D, DD)

    return A, B, C, D


# ステップ5. 出力
def finalize(A, B, C, D):
    return words_to_bytes((A, B, C, D)).hex()


# MD5の計算
def md5_hexdigest(input_bytes):
    # ステップ1. メッセージの拡張
    padded_bytes = add_padding(input_bytes)
    assert (len(padded_bytes) * 8) % 512 == 448, padded_bytes

    # bytesをwords（32bits以内のintのlist）に変換
    padded_words = bytes_to_words(padded_bytes)
    # 512bitsで割ったら448bits余る = 64bytesで割ったら56bytes余る = 16wordsで割ったら14words余る
    assert len(padded_words) % 16 == 14

    # ステップ2. メッセージに長さ付加
    padded_words_with_length = add_length(padded_words, len(input_bytes) * 8)
    # 512bitsの倍数 = 64bytesの倍数 = 16wordsの倍数
    assert len(padded_words_with_length) % 16 == 0

    # ステップ3. バッファの初期化
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # ステップ4. 算出処理
    for i in range(0, len(padded_words_with_length), 16):
        X = padded_words_with_length[i:i+16]
        A, B, C, D = calculate_MD5(X, A, B, C, D)

    # ステップ5. 出力
    hex_hash = finalize(A, B, C, D)
    return hex_hash


##############################################################
# テスト
##############################################################

import hashlib


def test_md5(string):
    print("## '{0}'".format(string))
    my_digest = md5_hexdigest(string.encode('utf-8'))
    builtin_digest = hashlib.md5(string.encode('utf-8')).hexdigest()
    print(my_digest)
    print(builtin_digest)
    print()
    assert my_digest == builtin_digest


test_md5("")
test_md5("a")
test_md5("abc")
test_md5("message digest")
test_md5("abcdefghijklmnopqrstuvwxyz")
test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123")
test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
test_md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
test_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
test_md5("ああああああああああああああああああああああああ")
