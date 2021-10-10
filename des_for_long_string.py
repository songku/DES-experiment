'''
Description:
Author: dive668
Date: 2021-10-07 15:02:08
LastEditTime: 2021-10-07 17:10:09
'''
from functools import reduce
import numpy as np
import des_head
import math

"""
numpy.zeros(shape, dtype=float, order='C', *, like=None)
0数组，以shape和dtype的类型order的顺序，填充
"""


# 辅助函数，整数转二进制，指定位长为n，大端法
def int2binlist(a, n):
    # 对于加密函数，传入的plaintext是16进制，此时在之前添加把它视为a=int(a,16)，不然程序遇到断言会报错，a是一个十六进制字符串a={str}'0x770b4317'
    # 对于res扩展函数，传入的a确实是一个S盒的一个数，是一个int
    assert 0 <= n and a < 2 ** n
    res = np.zeros(n, dtype=int)

    for x in range(n):
        res[n - x - 1] = a % 2
        a = a // 2
    return res.tolist()


assert int2binlist(0x1a, 10) == [0, 0, 0, 0, 0, 1, 1, 0, 1, 0]


# 辅助函数，整数转二进制字符串
def int2binstr(a):
    string = ""
    while a != 0:
        string += str(a % 2)
        a = a // 2
    return string[::-1]


# 待写binstr2int/binstr2hex,先将binstr转为binlist，再调用binlist2int
def binstr2int(a):
    x = [int(i) for i in a]
    return binlist2int(x)


# 二进制串转为列表
def binstr2list(string):
    return [x for x in string]


# 辅助函数，二进制数组转为整数，大端法
def binlist2int(a):
    return reduce(lambda x, y: x * 2 + y, a)  # 十进制到二进制的2倍率转换


assert binlist2int([0, 0, 0, 0, 0, 1, 1, 0, 1, 0]) == 0x1a


# 名字转换为int
def name2int(name):
    return int(binlist2int(name.encode("utf-8")))


# 字符用ascii转二进制串，佳哥代码
def str2bin(str):
    res = ""
    for i in str:
        tmp = bin(ord(i))[2:]  # 字符串转ascii，再转为二进制，并去掉前面的0b
        for j in range(0, 8 - len(tmp)):  # 补齐8位
            tmp = '0' + tmp  # 把输出的b给去掉
        res += tmp  # 字符串逐渐连成串
    return res


# 名字转key(64位二进制string)类型
def name2key(name):
    key_name_int = name2int(name)
    key_name_bin = '{:064b}'.format(key_name_int)
    print(key_name_bin)
    return key_name_bin


# 密钥字符串，不要汉字！！！转为int
def zh2int(string):
    string_list = [x for x in string]
    string_int = 0
    for i in range(len(string)):
        string_int += ord(string[i])
    return string_int


# 对输入字符串，输入字符串的范围是0-128，十六进制字符，加密为plaintext
def str2plaintext(string):
    if len(string) > 8:
        print("length of the word is so long!")
        exit(0)
    bin_string = ""
    for i in string:
        bin_string += int2binstr(ord(i)).zfill(8)  # 这里调用int2binstr，识别的应该是由字符转为的十进制的int
    return bin_string.zfill(64)


# 对输入16进制串，解密为plaintext
def plaintextdecode(hexstring):
    hex_list = []
    hex_string = ""
    hexstring = hexstring.replace('0x', '')  # 去掉0x
    length = int(len(hexstring) / 2)
    for i in range(length):
        hex_list.append(hexstring[2 * i:2 * i + 2])
    for i in range(length):
        hex_list[i] = "0x" + hex_list[i]
        hex_list[i] = int(hex_list[i], 16)
        hex_list[i] = chr(hex_list[i])
        hex_string += hex_list[i]
    return hex_string


# 二进制异或算法
def binXor(a, b):
    assert len(a) == len(b)
    """
    zip() 函数用于将可迭代的对象作为参数，将对象中对应的元素打包成
    一个个元组，然后返回由这些元组组成的列表。
    """
    return [x ^ y for x, y in zip(a, b)]


assert binXor([1, 1, 0, 1], [0, 1, 1, 0]) == [1, 0, 1, 1]


# 根据名字生成初始密钥算法
# def key_init(name):
#     retrun name

# 选择置换，对64位密钥key生成56位，并返回左右两半部分
def PC1(key):
    return [key[x - 1] for x in des_head.pc1_l], [key[x - 1] for x in des_head.pc1_r]


# 子密钥生成，由PC1生成16个48位子密钥
def keyGen(key):
    assert len(key) == 64  # 断言，用以判断一个表达式，在表达式条件为 false 的时候触发异常。

    l, r = PC1(key)  # l,r两个分别是28位的左右数组

    res = []  # 存储16个子密钥

    for x in range(16):
        l = leftRotate(l, des_head.off[x])  # 左半部分的循环左移
        r = leftRotate(r, des_head.off[x])  # 右半部分的循环左移

        res.append(PC2(l + r))

    return res


def leftRotate(a, off):
    # 用到了python列表的切片【start:end:step】
    # 左移的理解：从off处取右部分，补上从开头到off处
    return a[off:] + a[:off]


assert leftRotate([1, 0, 1, 1, 0], 2) == [1, 1, 0, 1, 0]


# 简单置换PC2，将左右密钥拼接并选取48位形成子密钥
def PC2(key):
    assert len(key) == 56

    return [key[x - 1] for x in des_head.pc2]


# 以上，我们调用keyGen()，返回16个48位子密钥的密钥数组res[]

# 加密算法
def Des(plain, key, method):
    # 将64位的二进制key字符串转为list，并生成子密钥数组subkeys
    subkeys = keyGen(int2binlist(key, 64))

    if method == 'decrypt':
        # 解密就是轮密钥倒过来使用
        subkeys = subkeys[::-1]
    # 对密文进行64位填充，并消除0x，转为2进制串并进行初始置换(IP置换),plain必须传入一个数值型，而不能是str类型
    m = IP(int2binlist(plain, 64))

    l, r = np.array(m, dtype=int).reshape(2, -1).tolist()

    for i in range(16):
        # goRound对l,r子序列和子密钥进行处理
        l, r = goRound(l, r, subkeys[i])

    return binlist2int(FP(r + l))


# 初始置换
# 初始置换
def IP(a):
    return [a[x - 1] for x in des_head.ip]


# 最终置换，与IP互逆
def FP(a):
    return [a[x - 1] for x in des_head.fp]


# 10轮迭代加密，每轮的处理
def goRound(l, r, subkey):
    return r, binXor(l, Feistel(r, subkey))


# F函数，轮函数的处理，des安全性的关键
def Feistel(a, subkey):
    assert len(a) == 32
    assert len(subkey) == 48

    # 扩展a为48位再与subkey异或
    t = binXor(Expand(a), subkey)
    t = S(t)
    t = P(t)

    return t


# 扩展算法，根据扩展矩阵，扩展为2进制矩阵
def Expand(a):
    assert len(a) == 32

    return [a[x - 1] for x in des_head.exp]


# P置换函数
def P(a):
    assert len(a) == 32

    return [a[x - 1] for x in des_head.p]


# S盒函数，本质也是一个置换关系
# 来自明文和subkey的48位xor结果，分成8组，每组6位，在8个S盒中对应
def S(a):
    assert len(a) == 48

    a = np.array(a, dtype=int).reshape(8, 6)
    res = []

    for i in range(8):
        # 用S_box[i]处理6位a[i]，得到4位输出

        p = a[i]
        r = des_head.S_box[i][binlist2int([p[0], p[5], p[1], p[2], p[3], p[4]])]
        res.append(int2binlist(r, 4))

    res = np.array(res).flatten().tolist()

    assert len(res) == 32
    return res


def encrypt(key):
    print("input the word you want to encrypt:")
    string = input()
    cipherstring = ""  # 最终的汇总密文串
    length = int(math.ceil(len(string) / 8)) #向上取整数
    for i in range(length):
        string_part=string[8*i:8*i+8]
        plaintext_part = str2plaintext(string_part)
        plaintext_int_part = binstr2int(plaintext_part)
        plaintext_hex_part = hex(plaintext_int_part)  # hex得到的是字符串，在int2binlist时出错
        print("待加密的十六级进制:{}".format(plaintext_hex_part))
        print("待加密二进制串:{}".format(plaintext_part))
        ciphertext_part = hex(Des(plaintext_int_part, key, "encrypt"))  # 传入的plaintext是64位0，1，64
        print("第{}段字符串的加密结果是{}".format(i,ciphertext_part))
        cipherstring+=ciphertext_part
    print("最终加密结果为:{}".format(cipherstring))

def decrypt(key):
    print("input the word you want to decrypt:")
    plaintext="" #完整的名文串
    string = input()
    length=math.ceil(int(len(string)/18))
    for i in range(length):
        string_part=string[i*18:i*18+18]
        string2int = int(string_part, 16)  # 以16进制串的形式看待string，并转为int整数
        print("待解密的十六进制串转为的int:{}".format(string2int))
        plaintext_raw = hex(Des(string2int, key, "decrypt"))  # 获得解码字符串的int值
        print("解完密的十六进制串:{}".format(plaintext_raw))
        print("解完密的十六进制串转为ascii有意义的明文如下")
        plaintext_dec = plaintextdecode(plaintext_raw)  # 16进制解码字符串通过ascii转换，转为有意义的原明文字符
        print("第{}段解密的明文:{}".format(i,plaintext_dec))
        plaintext+=plaintext_dec
    print("完整的解析后的明文如下")
    print(plaintext)


def method_check(name):
    key = zh2int(name)
    # key_int=binstr2int(key) #将64位key串转为int
    # key_hex=hex(key_int) #将int转为hex，便于传入Des函数
    print("do you want to encrypt or decrypt:")
    method = input()
    if method == "encrypt":
        encrypt(key)
    elif method == "decrypt":
        decrypt(key)
    else:
        print("the method you offered can not be checked,please rewrite again!")
        exit(0)


if __name__ == "__main__":
    print("input your name:")
    name = input()
    #key = name2key(name)  # key是64位串
    #print("name to key:{} to {}".format(name, key))
    method_check(name)
