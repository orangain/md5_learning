"""
参考URL
C言語での実装例：http://bkclass.web.fc2.com/doc_md5.html
RFC：https://www.ietf.org/rfc/rfc1321.txt
RFC邦訳：http://www.ipa.go.jp/security/rfc/RFC1321JA.html（ソースコードは原本から抜け落ちている箇所あり）
RFCのソースコードを実行する上で64bit対応するためのテクニック：
http://www.gcd.org/blog/2010/03/556/
"""

##############################################################
#基本のビット演算や文字列、ビット、整数、16進数の相互変換メソッド群
#Pythonはビット演算が独自仕様のため、一般的なビット演算を実現
##############################################################
# ビットを指定したビット長に直す
def set_blen(b, l):
    if len(b) <= l:
        return b.zfill(l)
    else:
        return b[len(b)-l:]

# 整数をビットに変換
def itob(i, l = None):
    b = bin(i)[2:]
    return b if l == None else set_blen(b, l)

# ビットを整数に変換
def btoi(b):
    return int(b,2)
    
# 16進数をビットに変換
def htob(h, l = None):
    return itob(int(h,16), l)

# ビットを16進数に変換
def btoh(b):
    return "".join(hex(int(b[i:i+4], 2))[2:] for i in range(0,len(b),4))

# 文字列をビットに変換
def stob(s, e='utf8'):
    if len(s) == 0:
        return ""
    else:
        import binascii
        b = htob(binascii.hexlify(s.encode(e)).decode(e))
        if len(b) % 8 != 0:
            b = "0" * (8 - len(b) % 8) + b
        return b

# ビット演算におけるAND
def AND(b1, b2, l = None):
    if l != None:
        b1 = set_blen(b1, l)
        b2 = set_blen(b2, l)
        b = itob(btoi(b1) & btoi(b2))
        return set_blen(b, l)
    return itob(btoi(b1) & btoi(b2))

# ビット演算におけるOR
def OR(b1, b2, l = None):
    if l != None:
        b1 = set_blen(b1, l)
        b2 = set_blen(b2, l)
        b = itob(btoi(b1) | btoi(b2))
        return set_blen(b, l)
    return itob(btoi(b1) | btoi(b2))

# ビット演算におけるXOR
def XOR(b1, b2, l = None):
    if l != None:
        b1 = set_blen(b1, l)
        b2 = set_blen(b2, l)
        b = itob(btoi(b1) ^ btoi(b2))
        return set_blen(b, l)
    return itob(btoi(b1) ^ btoi(b2))

# ビット演算におけるNOT
def NOT(b1, l=None):
    if l != None:
        b1 = set_blen(b1, l)
    return "".join(['0' if i == '1' else '1' for i in b1])

# ビット演算における左シフト
def L_SHIFT(b1, d, l = None):
    b = itob(btoi(b1) << d)
    return b if l == None else set_blen(b, l)

# ビット演算における右シフト
def R_SHIFT(b1, d, l = None):
    b = itob(btoi(b1) >> d)
    if l == None:
        return b
    else:
        if l > len(b):
            return '1'*(l-len(b)) + b
        else:
            return set_blen(b, l)

# ビット演算における左ローテート
def L_ROTATE(b, d):
    if len(b) == 1:
        return b
    else:
        for _ in range(0,d):
            b = b[1:] + b[0]
        return b
    
# ビット演算における右ローテート（今回は使わない）
def R_ROTATE(b, d):
    if len(b) == 1:
        return b
    else:
        for _ in range(0,d):
            b = b[-1:] + b[:-1]
        return b

# ビットをバイト毎に反転
# 10001011010111011100101101010011
# -> 1:10001011 2:01011101 3:11001011 4:01010011
# -> 4:01010011 3:11001011 2:01011101 1:10001011 
# -> 01010011110010110101110110001011 
def reverse_bits(bits):
    reversed_bits = ""
    for i in range(len(bits)-8, -1 , -8): 
        reversed_bits += bits[i : i+8]
    return reversed_bits

##############################################################
# RFCに則ったMD5の実装
##############################################################    
# ステップ1. メッセージの拡張
def padding_to_bits(bits):
    bits_length = len(bits)
    if bits_length % 512 < 448:
        padding_length = 448 - bits_length % 512
    elif 448 <= bits_length % 512 <= 512:
        padding_length = 512 - bits_length % 512 + 448
    padding = ['0' for _ in range(padding_length)]
    padding[0] = '1'
    padding = "".join(padding)
    paddinged_bits = bits + padding
    return paddinged_bits

# ステップ2. メッセージに長さ付加
def add_bits_length(bits, paddinged_bits):
    bits_length = itob(len(bits))
    bits_length = bits_length if len(bits_length) < pow(2,64) else bits_length[pow(2,64):]
    bits_length = set_blen(bits_length, 64)
    paddinged_bits += reverse_bits(bits_length)
    return paddinged_bits

# ステップ3. バッファの初期化
def initialize_buffer():
    buffer = dict(
        A = htob('0x67452301',32),
        B = htob('0xefcdab89',32),
        C = htob('0x98badcfe',32),
        D = htob('0x10325476',32),
    )
    return buffer

# 計算用数値配列の準備
def get_array_for_culculate():
    T = ['0']
    from math import sin
    for i in range (1, 64+1, 1):
        T.append(int(4294967296 * abs(sin(i))))
    return T

# 
def get_array_X(bits):
    X = []
    for i in range(0, 512, 32):
        X.append(reverse_bits(bits[i:i+32]))
    return X

def base_calc(a, b, c, d, x, s, ac, calc):
    temp_a = btoi(a)
    temp_a += btoi(calc(b, c, d)) + btoi(x) + int(ac)
    temp_a = btoi(L_ROTATE(itob(temp_a,32), s))
    temp_a += btoi(b)
    return itob(temp_a,32)

def F(X,Y,Z):
    l = 32
    return OR( AND( X, Y, l) , AND( NOT(X) , Z, l ), l )

def FF(a, b, c, d, x, s, ac):
    return base_calc(a, b, c, d, x, s, ac, F)

def G(X,Y,Z):
    l = 32
    return OR( AND( X , Z, l) , AND( Y , NOT(Z), l), l )

def GG(a, b, c, d, x, s, ac):
    return base_calc(a, b, c, d, x, s, ac, G)

# 補助関数の定義
def H(X,Y,Z):
    l = 32
    return XOR( XOR(X , Y, l) , Z ,l )

def HH(a, b, c, d, x, s, ac):
    return base_calc(a, b, c, d, x, s, ac, H)

def I(X,Y,Z):
    l = 32
    return XOR( Y , OR( X , NOT(Z), l ), l )

def II(a, b, c, d, x, s, ac):
    return base_calc(a, b, c, d, x, s, ac, I)


# 算出処理
def culuculate_MD5(bits, buffer):
    T = get_array_for_culculate()
    X = get_array_X(bits)

    # 初期値の退避
    import copy
    buffer_org = copy.deepcopy(buffer)
    AA = buffer_org['A']
    BB = buffer_org['B']
    CC = buffer_org['C']
    DD = buffer_org['D']

    A = buffer['A']
    B = buffer['B']
    C = buffer['C']
    D = buffer['D']

    # 第一段階
    for i in range(0, 16 , 4):
        A = FF(A, B, C, D, X[ i  ],  7, T[ i+1])
        D = FF(D, A, B, C, X[ i+1], 12, T[ i+2])
        C = FF(C, D, A, B, X[ i+2], 17, T[ i+3])
        B = FF(B, C, D, A, X[ i+3], 22, T[ i+4])
    
    def check_max(i):
        return i if  i <= 16 else  i - 16
    def check_min(i):
        return i if  i >=  0 else  i + 16

    # 第二段階
    for i in range(0, 16 , 4):
        x1 = check_max( 1 + i) 
        x2 = check_max( 6 + i)
        x3 = check_max(11 + i)
        x4 = check_max( 0 + i)
        A = GG(A, B, C, D, X[ x1],  5, T[ i+17])
        D = GG(D, A, B, C, X[ x2],  9, T[ i+18])
        C = GG(C, D, A, B, X[ x3], 14, T[ i+19])
        B = GG(B, C, D, A, X[ x4], 20, T[ i+20])
    
    # 第三段階
    for i in range(0, 16 , 4):
        x1 = check_min( 5 - i) 
        x2 = check_min( 8 - i)
        x3 = check_min(11 - i)
        x4 = check_min(14 - i)
        A = HH(A, B, C, D, X[ x1],  4, T[ i+33])
        D = HH(D, A, B, C, X[ x2], 11, T[ i+34])
        C = HH(C, D, A, B, X[ x3], 16, T[ i+35])
        B = HH(B, C, D, A, X[ x4], 23, T[ i+36])

    # 第四段階
    for i in range(0, 16 , 4):
        x1 = check_min( 0 - i) 
        x2 = check_min( 7 - i)
        x3 = check_min(14 - i)
        x4 = check_min( 5 - i)
        A = II(A, B, C, D, X[ x1],  6, T[ i+49])
        D = II(D, A, B, C, X[ x2], 10, T[ i+50])
        C = II(C, D, A, B, X[ x3], 15, T[ i+51])
        B = II(B, C, D, A, X[ x4], 21, T[ i+52])

    result_buffer = dict(
        A = itob(btoi(A) + btoi(AA),32),
        B = itob(btoi(B) + btoi(BB),32),
        C = itob(btoi(C) + btoi(CC),32),
        D = itob(btoi(D) + btoi(DD),32),
    )

    return result_buffer

# 5.出力
def finalize(buffer):
    hex_hash = ""
    hex_hash += btoh(reverse_bits(buffer['A']))
    hex_hash += btoh(reverse_bits(buffer['B']))
    hex_hash += btoh(reverse_bits(buffer['C']))
    hex_hash += btoh(reverse_bits(buffer['D']))

    return hex_hash

def md5_hexdigest(string):
    # ステップ0. メッセージのbit化
    bits = stob(string)
    # ステップ1. メッセージの拡張
    paddinged_bits = padding_to_bits(bits)
    # ステップ2. メッセージに長さ付加
    fixed_paddinged_bits = add_bits_length(bits,paddinged_bits)
    # ステップ3. バッファの初期化
    buffer = initialize_buffer()
    # ステップ4. 算出処理
    for i in range(0,len(fixed_paddinged_bits),512):
        part_bits = fixed_paddinged_bits[i:i+512]
        buffer = culuculate_MD5(part_bits, buffer)
    # ステップ5. 出力
    hex_hash = finalize(buffer)
    return hex_hash


##############################################################
# テスト
##############################################################    

import hashlib

print("## '' ")
print(md5_hexdigest(""))
print(hashlib.md5("".encode('utf8')).hexdigest())
print("")

print("## 'a' ")
print(md5_hexdigest("a"))
print(hashlib.md5("a".encode('utf8')).hexdigest())
print("")

print("## 'abc' ")
print(md5_hexdigest("abc"))
print(hashlib.md5("abc".encode('utf8')).hexdigest())
print("")

print("## 'message digest' ")
print(md5_hexdigest("message digest"))
print(hashlib.md5("message digest".encode('utf8')).hexdigest())
print("")

print("## 'abcdefghijklmnopqrstuvwxyz' ")
print(md5_hexdigest("abcdefghijklmnopqrstuvwxyz"))
print(hashlib.md5("abcdefghijklmnopqrstuvwxyz".encode('utf8')).hexdigest())
print("")

print("## 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123' ")
print(md5_hexdigest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123"))
print(hashlib.md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123".encode('utf8')).hexdigest())
print("")

print("## 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' ")
print(md5_hexdigest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
print(hashlib.md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".encode('utf8')).hexdigest())
print("")

print("## '12345678901234567890123456789012345678901234567890123456789012345678901234567890' ")
print(md5_hexdigest("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
print(hashlib.md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890".encode('utf8')).hexdigest())
print("")

print("## 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' ")
print(md5_hexdigest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
print(hashlib.md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".encode('utf8')).hexdigest())
print("")

print("## 'ああああああああああああああああああああああああ' ")
print(md5_hexdigest("ああああああああああああああああああああああああ"))
print(hashlib.md5("ああああああああああああああああああああああああ".encode('utf8')).hexdigest())
