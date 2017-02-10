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

# ステップ2. メッセージに長さ付加

# ステップ3. バッファの初期化

# 計算用数値配列の準備

# 

# 補助関数の定義

# 算出処理


def md5_hexdigest(string):
    hex_hash = ""
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
