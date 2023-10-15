from charm.core.engine.protocol import *
from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import prime256v1
from base64 import encodebytes, decodebytes
import random
from Crypto.Hash import SHA256
import time
from Crypto import Random
from Crypto.Cipher import AES
from functools import reduce
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair


def element_to_bytes(element, group):

    # 序列化元素为字节形式

    serialized_bytes = group.serialize(element)

    return serialized_bytes


def bytes_to_element(element_bytes, group):

    element = group.deserialize(byte_bytes)

    return element


pairing_group = PairingGroup('SS512')
BS = 16
def pad(s): return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad(s): return s[:-ord(s[len(s)-1:])]


def aes_encrypt(key, raw):
    assert len(key) == 32
    raw = pad(raw.decode("ISO-8859-1"))  # bytes to string

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(raw.encode("ISO-8859-1")))  # string to bytes


def aes_decrypt(key, enc):
    enc = (enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


aesKey1 = random._urandom(32)
print("aesKey1---", aesKey1, "----", len(aesKey1))
pairing_group = PairingGroup('SS512')
aesKey = pairing_group.random(GT)
aesKey_bytes = element_to_bytes(aesKey, pairing_group)
print("aesKey_bytes---", aesKey_bytes, "---", len(aesKey_bytes))
aesKey_bytes32 = aesKey_bytes[0:32]
encryption = encrypt(aesKey_bytes32, b'hello')
print("encryption---", encryption, "---", len(encryption.decode("ISO-8859-1")))
decryption = decrypt(aesKey_bytes32, encryption)

print(decryption)
