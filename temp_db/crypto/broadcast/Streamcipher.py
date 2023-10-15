from itertools import cycle
import base64
import os
import pickle

def generateStreamkey():
    num_digits = 32
    key = os.urandom(int(num_digits / 2))
    f = open("./config/streamcipher.keys","wb+")
    f.write( pickle.dumps(key)  )
    f.close()

def xor_crypt_string(data, key, encode=False, decode=False):
    if decode:
        data = base64.decodebytes(data)
    xored = ''.join(chr(x ^ y) for (x,y) in zip(data, cycle(key))).encode("ISO-8859-1")
    
    if encode:
        return base64.encodebytes(xored).strip()
    return xored

'''
secret_data = "239054".encode("ISO-8859-1")
num_digits = 32
key = os.urandom(int(num_digits / 2))
a = xor_crypt_string(secret_data, key, encode=True)
print ("a---",a.decode("ISO-8859-1"))
aa = xor_crypt_string(a,key, decode=True)
print ("aa---",aa.decode("ISO-8859-1"))
'''
