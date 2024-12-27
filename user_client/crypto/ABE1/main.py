from charm.core.engine.protocol import *
from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import prime256v1
import random
from Crypto.Hash import SHA256
import time
from Crypto import Random
from Crypto.Cipher import AES
from functools import reduce
from ABE.ac17 import AC17CPABE
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from ABE.msp import MSP
import pickle
from att_decrypt import *
from att_encrypt import *
from pack_struct import *
from unpack_struct import *


def element_to_bytes(element):
    group = PairingGroup('SS512')
    serialized_bytes = group.serialize(element)

    return serialized_bytes


def bytes_to_element(element_bytes):
    group = PairingGroup('SS512')
    element = group.deserialize(element_bytes)

    return element


def main():

    tx = "abcdefg"
    policy_str = '((ONE and THREE) and (TWO OR FOUR))'
    m = encrypt(policy_str, tx.encode("ISO-8859-1"))
    b = attribute_pack(m)
    # print("m---",m)
    mm = attribute_unpack(b)
    # print("mm---",mm)
    x1 = m[0]
    x2 = mm[0]
    y1 = m[1]
    y2 = mm[1]
    attr_list = ['ONE', 'TWO', 'THREE']
    decryption = decrypt(attr_list, mm)
    print(decryption)


'''




BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]


def element_to_bytes(element):
    group = PairingGroup('SS512')
    serialized_bytes = group.serialize(element)

    return serialized_bytes

def bytes_to_element(element_bytes):
    group = PairingGroup('SS512')
    element = group.deserialize(element_bytes)

    return element

def Generate_attribute_key():
    pairing_group = PairingGroup('SS512')
    cpabe = AC17CPABE(pairing_group, 2)
    (pk, msk) = cpabe.setup()
    #print("pk---",pk)
    #print("msk---",msk)
    pk_list = []
    msk_list = []
    pk_list.append(len(pk))
    for a in pk:
        pk_list.append(a)
        b = pk[a]
        pk_list.append(len(b))
        for c in b:
            d = element_to_bytes(c)
            pk_list.append(d)

    for a in msk:
        msk_list.append(a)
        b = msk[a]
        if a == 'g' or a == 'h':
            d = element_to_bytes(b)
            msk_list.append(d)
        else:
            msk_list.append(len(b))
            for c in b:
                d = element_to_bytes(c)
                msk_list.append(d)
    
    with open("./attribute_key/pk.keys","wb+") as f:
        pickle.dump(pk_list,f)

    with open("./attribute_key/msk.keys","wb+") as f:
        pickle.dump(msk_list,f)
    
def out_key():
    filename = "./attribute_key/pk.keys"
    with open(filename, 'rb') as f:
        pk_list = pickle.load(f)
    #print("pk_list---",pk_list,"---",type(pk_list))
    filename = "./attribute_key/msk.keys"
    with open(filename, 'rb') as f:
        msk_list = pickle.load(f)
    #print("msk_list---",msk_list,"---",type(msk_list))
    
    h_A = []
    e_gh_kA = []
    j = 1
    h_A_str = pk_list[j]
    j+=1 
    for i in range(pk_list[j]):
        j+=1
        e = bytes_to_element(pk_list[j])
        h_A.append(e)
    j+=1
    e_gh_kA_str = pk_list[j]
    j+=1
    for i in range(pk_list[j]):
        j+=1
        e = bytes_to_element(pk_list[j])
        e_gh_kA.append(e)
    pk = {'h_A': h_A, 'e_gh_kA': e_gh_kA}
    
    j = 0
    g_str = msk_list[j]
    j += 1
    g = bytes_to_element(msk_list[j])
    j += 1
    h_str = msk_list[j]
    j += 1
    h = bytes_to_element(msk_list[j])
    j += 1
    g_k = []
    A = []
    B = []
    g_k_str = msk_list[j]
    j +=1
    for i in range(msk_list[j]):
        j += 1
        e = bytes_to_element(msk_list[j])
        g_k.append(e)
    j+=1
    A_str = msk_list[j]
    j+=1
    for i in range(msk_list[j]):
        j += 1
        e = bytes_to_element(msk_list[j])
        A.append(e)
    j+=1
    B_str = msk_list[j]
    j+=1
    for i in range(msk_list[j]):
        j += 1
        e = bytes_to_element(msk_list[j])
        B.append(e)
    msk = {'g': g, 'h': h, 'g_k': g_k, 'A': A, 'B': B}
    
    return (pk, msk)
    
def aes_encrypt(key, raw):
    assert len(key) == 32
    raw = pad(raw.decode("ISO-8859-1")) #bytes to string
  
    iv = Random.new().read( AES.block_size )
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return ( iv + cipher.encrypt( raw.encode("ISO-8859-1") ) )  #string to bytes

def aes_decrypt( key, enc ):
    enc = (enc)
    iv = enc[:16]
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[16:] ))


def encrypt(policy_str, tx):
    pairing_group = PairingGroup('SS512')
    msg = pairing_group.random(GT)
    (pk, msk) = out_key()
    cpabe = AC17CPABE(pairing_group, 2)
    ctxt = cpabe.encrypt(pk, msg, policy_str)
    aesKey_bytes = element_to_bytes(msg)
    aesKey_bytes32 = aesKey_bytes[0:32]
    encryption = aes_encrypt(aesKey_bytes32, tx)
    return (ctxt, encryption)

def decrypt(attr_list, ctxt, encryption):
    (pk, msk) = out_key()
    pairing_group = PairingGroup('SS512')
    cpabe = AC17CPABE(pairing_group, 2)
    key = cpabe.keygen(pk, msk, attr_list)
    rec_msg = cpabe.decrypt(pk, ctxt, key)
    aesKey_bytes = element_to_bytes(rec_msg)
    aesKey_bytes32 = aesKey_bytes[0:32]
    decryption = aes_decrypt(aesKey_bytes32,encryption)
    return decryption

def main():

    tx = "abcdefg"
    policy_str = '((ONE and THREE) and (TWO OR FOUR))'
    (ctxt, encryption) = encrypt(policy_str, tx.encode("ISO-8859-1"))
    
    attr_list = ['ONE', 'TWO', 'THREE']
    decryption = decrypt(attr_list, ctxt, encryption)
    print(decryption.decode("ISO-8859-1"))

    for a in ctxt:
        i+=1
        if i==1:
            print(a,"---",type(a),"---",ctxt[a],"---",type(ctxt[a]))
            b=str(ctxt[a])
            print("str(b)---",b,"---",type(b))
            verbose = False
            util = MSP(pairing_group, verbose)
            bb = util.createPolicy(b)
            if ctxt[a] == bb:
                print("bb---",bb,"---",type(bb))
        elif i==2:
            print(a,"---",type(a))
            for b in ctxt[a]:
                print(b,"---",type(b))
                b_bytes = element_to_bytes(b,pairing_group)
                print("b_bytes---",b_bytes)
                b_b_element = bytes_to_element(b_bytes,pairing_group)
                if b_b_element == b:
                    print("b_b_element---",b_b_element)
        elif i==3:
            print(a,"---",type(a))
            c=ctxt[a]
            print("len(c)---",len(c))
            for b in c:
                print(b,"---",type(b))
                for d in c[b]:
                    print(d,"---",type(d))
                    d_bytes = element_to_bytes(d,pairing_group)
                    print("d_bytes---",d_bytes)
                    d_b_element = bytes_to_element(d_bytes,pairing_group)
                    if d_b_element == d:
                        print("d_b_element---",d_b_element)
        elif i==4:
            print(a,"---",type(a),"---",ctxt[a],"---",type(ctxt[a]))
            b = ctxt[a]
            b_bytes = element_to_bytes(b,pairing_group)
            print("b_bytes---",b_bytes)
            b_b_element = bytes_to_element(b_bytes,pairing_group)
            if b_b_element == b:
                print("b_b_element---",b_b_element)
'''


if __name__ == "__main__":
    debug = True
    main()
