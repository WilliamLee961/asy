import os
import pickle
import random
from pathlib import Path

from crypto.threshold._aes import aes_encrypt, aes_decrypt
from crypto.threshold.tdh2 import deserialize, TDHPublicKey, TDHPrivateKey, strtobytes, serialize, deserialize1, deserialize2, \
    deserialize0, bytestostr, gtob, btog
import time
from Crypto.Hash import SHA256
import struct
from io import BytesIO

def Threshold_pack(C,cm):
    buf = BytesIO()
    Clen = len(C)
    buf.write(struct.pack("<i", Clen))
    for i in range(Clen):
        if i >= 2:
            x = gtob(C[i])
            buf.write(struct.pack("<i", len(x)))
            buf.write(x)
        else:
            buf.write(struct.pack("<i", len(C[i])))
            buf.write(C[i])
    buf.write(struct.pack("<i", len(cm)))
    buf.write(cm)
    buf.seek(0)
    return buf.read()

def Threshold_unpack(tx):
    buf = BytesIO(tx)
    Clen_bytes = buf.read(4)
    Clen, = struct.unpack("<i", Clen_bytes)
    C = []
    for i in range(Clen):
        if i >= 2:
            xlen_bytes = buf.read(4)
            xlen, = struct.unpack("<i", xlen_bytes)
            x_bytes = buf.read(xlen)
            x = btog(x_bytes)
            C.append(x)
        else:
            xlen_bytes = buf.read(4)
            xlen, = struct.unpack("<i", xlen_bytes)
            x_bytes = buf.read(xlen)
            C.append(x_bytes)

    cmlen_bytes = buf.read(4)
    cmlen, = struct.unpack("<i", cmlen_bytes)
    cm = buf.read(cmlen)

    return C, cm

def Threshold_encryption(m, ACL):
    with open("./crypto/threshold/thenc4_1.key", "rb") as f:
        (l, k, sVK, sVKs, SKs, gg) = pickle.load(f)

    g = deserialize(gg)
    PK, SKs = TDHPublicKey(l, k, deserialize(sVK), [deserialize(sVKp) for sVKp in sVKs]), \
        [TDHPrivateKey(l, k, deserialize(sVK), [deserialize(sVKp) for sVKp in sVKs], \
                       deserialize(SKp[1]), SKp[0]) for SKp in SKs]

    key = os.urandom(32)
    iv = key[0:16]

    cm = aes_encrypt(key, iv, m)

    L = SHA256.new(ACL.encode('utf-8')).digest()
    C = PK.encrypt(key, L, g)
    tx = Threshold_pack(C, cm)
    return tx

def share_pack(i,share,tx):
    buf = BytesIO()
    buf.write(struct.pack("<i", i))
    (a, b, c) = share
    ag = gtob(a)
    bg = gtob(b)
    cg = gtob(c)
    buf.write(struct.pack("<i", len(ag)))
    buf.write(ag)
    buf.write(struct.pack("<i", len(bg)))
    buf.write(bg)
    buf.write(struct.pack("<i", len(cg)))
    buf.write(cg)
    buf.write(struct.pack("<i", len(tx)))
    buf.write(tx)
    buf.seek(0)
    return buf.read()

def share_unpack(b):
    buf = BytesIO(b)
    i_bytes = buf.read(4)
    i, = struct.unpack("<i", i_bytes)
    aglen_bytes = buf.read(4)
    aglen, = struct.unpack("<i", aglen_bytes)
    ag_bytes = buf.read(aglen)
    a = btog(ag_bytes)
    bglen_bytes = buf.read(4)
    bglen, = struct.unpack("<i", bglen_bytes)
    bg_bytes = buf.read(bglen)
    b = btog(bg_bytes)
    cglen_bytes = buf.read(4)
    cglen, = struct.unpack("<i", cglen_bytes)
    cg_bytes = buf.read(cglen)
    c = btog(cg_bytes)
    share = (a, b, c)
    txlen_bytes = buf.read(4)
    txlen, = struct.unpack("<i", txlen_bytes)
    tx = buf.read(txlen)
    c = btog(cg_bytes)
    return i, share, tx

def share_i(i, tx):
    C ,cm = Threshold_unpack(tx)
    with open("./crypto/threshold/thenc4_1.key", "rb") as f:
        (l, k, sVK, sVKs, SKs, gg) = pickle.load(f)

    g = deserialize(gg)
    PK, SKs = TDHPublicKey(l, k, deserialize(sVK), [deserialize(sVKp) for sVKp in sVKs]), \
        [TDHPrivateKey(l, k, deserialize(sVK), [deserialize(sVKp) for sVKp in sVKs], \
                       deserialize(SKp[1]), SKp[0]) for SKp in SKs]

    share = SKs[i].decrypt_share(C, g)
    return share_pack(i, share, tx)


def Threshold_decryption(tx,T_key):
    C, cm = Threshold_unpack(tx)
    with open("./crypto/threshold/thenc4_1.key", "rb") as f:
        (l, k, sVK, sVKs, SKs, gg) = pickle.load(f)

    g = deserialize(gg)
    PK, SKs = TDHPublicKey(l, k, deserialize(sVK), [deserialize(sVKp) for sVKp in sVKs]), \
        [TDHPrivateKey(l, k, deserialize(sVK), [deserialize(sVKp) for sVKp in sVKs], \
                       deserialize(SKp[1]), SKp[0]) for SKp in SKs]

    key = PK.combine_shares(C, T_key)
    iv = key[0:16]
    m = aes_decrypt(key, iv, cm)
    print(m)
    return m
