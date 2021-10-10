'''
Description:
Author: dive668
Date: 2021-10-07 15:02:08
LastEditTime: 2021-10-07 17:10:09
'''
import des_for_long_string

"""
numpy.zeros(shape, dtype=float, order='C', *, like=None)
0数组，以shape和dtype的类型order的顺序，填充
"""
def passwd_check(password):
    with open('C:\\Users\\lkrwz\\Desktop\\password.txt','r') as f:
        password_saved=f.read()
        if password==password_saved:
            print("checked right!")
        else:
            print("password wrong!")

def method_check():
    method=input()
    if method=="create":
        print("input your password:")
        passwd=input()
        passwd_key=des_for_long_string.zh2int(passwd)
        passwd_encrypt=des_for_long_string.Des(0x1122334455667788,passwd_key,"encrypt")
        with open('C:\\Users\\lkrwz\\Desktop\\password.txt','w+') as f:
            f.write(hex(passwd_encrypt))
            print("your password is well well kept")
    elif method=="login":
        print("input your password:")
        passwd=input()
        passwd_key=des_for_long_string.zh2int(passwd)
        passwd_encrypt=des_for_long_string.Des(0x1122334455667788,passwd_key,"encrypt")
        passwd_check(hex(passwd_encrypt))

    else:
        print("the method you input is not valuable")
        exit(0)

if __name__=='__main__':
    print("do you want to create or login")
    method_check()