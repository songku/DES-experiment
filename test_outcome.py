#int2bin函数内如果是int(a,16)，则会是如下加密结果
# do you want to encrypt or decrypt:
# encrypt
# input the word you want to encrypt:
# what
# the encrypted ciphertext is 0xb837b7b2c5b4188c


#int2bin函数内如果是int(a)，会得到如下加密结果
# do you want to encrypt or decrypt:
# encrypt
# input the word you want to encrypt:
# what
# the encrypted ciphertext is 0xfda138f190a349

#in2bin函数内如果是int(a,2)
# do you want to encrypt or decrypt:
# encrypt
# input the word you want to encrypt:
# what
# the encrypted ciphertext is 0xcc30333245c1433a


# newest 2021.10.9
# 刘柯汝
# what
# 待加密十六进制串:0000000000000000000000000000000001110111000010110100001100010111
# the encrypted ciphertext is 0xc7da6ea3b0ac84e


# newest 2021.10.9
# xxx ->329(int)
#子密钥安全性特别差，很多位置都是0，只有要给位置是1
#int 2 binarylist，生成子密钥的res.list [000000000000000000000000000000000000000000000000000000101001001]->329
#name2key应该弃用，用到了utf-8，对输入字符串密钥(可以包括中文)进行变长加密
#name to key:xxx to 0000000000000000000000000000000000000000000000000000001011111000


#因为IP置换密钥，第一轮l,rl,r=PC1(key) l,r两个分别是28位的左右数组
#l:[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
#r:[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# encrypt
# input the word you want to encrypt:
# what
# char->ascii  119;104;97;116
# 119->01110111->77(hex)  104->01101000->68(hex)  97->01100001->61(hex)  116->01110100->74(hex)
# 待加密二进制串:0000000000000000000000000000000001110111000010110100001100010111 这里存在错误
# 正确的二进制串:0000000000000000000000000000000001110111011010000110000101110100' √
# 待加密十六进制串：'0x77686174' 正确的√
# 待加密串的int值：2003329396 正确的√
# a的int2string返回的string:1000011 返回前逆置得到 1100001√
# the encrypted ciphertext is 0x39e12066fb525120 √
# decrypt
# 待解密的十六进制串转为的int:4170650356597018912
# 解完密的十六进制串:0x77686174




# 待加密十六进制串：'0x770b4317' ×
# 待加密串的int值： 1997226775 ×
# the encrypted ciphertext is 0x57b065c1f1318194 ×
#decrypt
#cipherstring2int:6318662160850452884 checked right
#cipherstring2bin:0101011110110000011001011100000111110001001100011000000110010100 √
#进行初始IP置换，64位不失真
#得到m:[0,0,0,1,1,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,0,1,0,1,0,1,1,1,1,1,0,1,1,1,0,1,1,0,1,0,0,0,1,1,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
#得到解密的字符串：plaintext_raw：'0x770b4317'
#plaintextdecode函数存在问题：

#'0x770b4317' ×
#hex_list=list(hexstring[::2])  ['0', '7', '0', '4', '1']
#我们想要的hexlist本应该是['77','0b','43','17']

# string="刘柯汝"
#
# #汉字编码，不要接触汉字
# def zh2code(string):
#     string_list=[x for x in string]
#     string_int=0
#     for i in range(len(string)):
#         string_int+=ord(string[i])
#     return string_int
#
# print(zh2code("1235"))

#
# encrypt
# input the word you want to encrypt:
# liuyang
# 待加密的十六级进制:0x6c697579616e67
# 待加密二进制串:0000000001101100011010010111010101111001011000010110111001100111
# the encrypted ciphertext is 0x70bb869cc49f4070

# xxx ->encrypt
# dadadadadadada
# 待加密的十六级进制:0x6461646164616461
# 待加密二进制串:0110010001100001011001000110000101100100011000010110010001100001
# 第0段字符串的加密结果是0xd9f437d9f86ddfea
# 待加密的十六级进制:0x646164616461
# 待加密二进制串:0000000000000000011001000110000101100100011000010110010001100001
# 第1段字符串的加密结果是0xeb3a260de6f209a5
# 最终加密结果为:0xd9f437d9f86ddfea0xeb3a260de6f209a5


# iamlixiaohua
# 待加密的十六级进制:0x69616d6c69786961
# 待加密二进制串:0110100101100001011011010110110001101001011110000110100101100001
# 第0段字符串的加密结果是0x45cc38e25bfcb5d8
# 待加密的十六级进制:0x6f687561
# 待加密二进制串:0000000000000000000000000000000001101111011010000111010101100001
# 第1段字符串的加密结果是0x769a905b6e19bbd6
# 最终加密结果为:0x45cc38e25bfcb5d80x769a905b6e19bbd60x45cc38e25bfcb5d80x769a905b6e19bbd6