from typing import Any

import socket
import hashlib
import struct
from io import BytesIO
from crypto.rsa.rsa_main import rsa_encipher
from crypto.threshold._threshold import Threshold_encryption
from struct_package.pack_struct import _pack, broadcast_pack, attribute_pack
from crypto.broadcast.generateBroadcastkeys import Broadcast_encryption
from crypto.ABE1.att_encrypt import *
from Crypto.PublicKey import RSA
import logging
import os
import string
import random
import threading

n = 1
txs = [None] * (n + 10)


def tx_generator(size=250, chars=string.ascii_uppercase + string.digits):
    return '<Dummy TX: ' + ''.join(random.choice(chars) for _ in range(size - 10)) + '>'


def write_time_log():
    logger = logging.getLogger("write_time")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "write_time" + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    logger.addHandler(file_handler)
    return logger


def _hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def get_len(msg):
    buf = BytesIO()
    buf.write(struct.pack("<i", len(msg)))
    buf.write(msg)
    buf.seek(0)
    return buf.read()


def Client_send(host, port, tx):
    try:
        sk = socket.socket()
        sk.connect((host, port))
        _tx = get_len(tx)
        sk.sendall(_tx)
        # data = sk.recv(1024)
        # print("tx---",len(_tx))
        sk.close()
    except:
        print("NO")


def tyke_str(tyke):
    if tyke == 1:
        return "Broadcast encryption"
    elif tyke == 3:
        return "Attribute encryption"
    elif tyke == 5:
        return "Threshold encryption"


def _pack_chain(tyke, key_chain, chm, ccACL):
    fields = {"key": key_chain, "value": ""}
    value = {"Encryption method": tyke_str(tyke), "key": chm, "ACL": ccACL}
    fields["value"] = json.dumps(value)

    fields = json.dumps(fields)
    fields_b = fields.encode()
    print("fields---", len(fields_b))
    return fields_b


def key_streamcipher_gen():
    filename = "./config/streamcipher.keys"
    key_streamcipher = open(filename, 'rb').read()
    return key_streamcipher


def rsa_keygen():
    with open('rsa_key/PK.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    return public_key


def attribute_keygen():
    return out_key()


def _Broadcast(i, id, m):
    key_chain = str(id)
    print("key_chain---", key_chain)
    nodes_deleted = [4]
    public_key = rsa_keygen()
    key_streamcipher = key_streamcipher_gen()
    ACL = [3, 5, 6]
    ACL = ', '.join(map(str, ACL))
    ccACL = rsa_encipher(public_key, ACL.encode(
        "ISO-8859-1")).decode("ISO-8859-1")
    hm = _hash(m)
    cm = Broadcast_encryption(4, nodes_deleted, key_streamcipher, m)
    chm = Broadcast_encryption(4, nodes_deleted, key_streamcipher, hm)
    chm_str = broadcast_pack(chm).decode("ISO-8859-1")
    tyke = 1
    fields = _pack_chain(tyke, key_chain, chm_str, ccACL)
    buf = _pack(tyke, fields, hm, cm)
    txs[i] = buf


def _Attribute(i, id, m):
    key_chain = str(id)
    print("key_chain---", key_chain)
    (pk, msk) = attribute_keygen()
    policy_str = '((ONE and THREE) and (TWO OR FOUR))'
    ACL = policy_str
    public_key = rsa_keygen()
    ccACL = rsa_encipher(public_key, ACL.encode(
        "ISO-8859-1")).decode("ISO-8859-1")
    hm = _hash(m)
    cm = encrypt(pk, msk, policy_str, m)
    chm = encrypt(pk, msk, policy_str, hm)
    chm_str = attribute_pack(chm).decode("ISO-8859-1")
    tyke = 3
    fields = _pack_chain(tyke, key_chain, chm_str, ccACL)
    buf = _pack(tyke, fields, hm, cm)
    txs[i] = buf


def _Threshold(i, id, m):
    key_chain = str(id)
    print("key_chain---", key_chain)
    hm = _hash(m)
    chm = hm.decode("ISO-8859-1")
    ACL = 'label'
    public_key = rsa_keygen()
    ccACL = rsa_encipher(public_key, ACL.encode(
        "ISO-8859-1")).decode("ISO-8859-1")
    cm = Threshold_encryption(m, ACL)
    tyke = 5
    fields = _pack_chain(tyke, key_chain, chm, ccACL)
    buf = _pack(tyke, fields, hm, cm)
    txs[i] = buf


def main():
    N = 4
    mes_addresses = [None] * N
    with open('hosts_message.config', 'r') as hosts:
        for line in hosts:
            params = line.split()
            pid = int(params[0])
            priv_ip = params[1]
            pub_ip = params[2]
            port = int(params[3])
            # print(pid, priv_ip ,pub_ip ,port)
            if pid not in range(N):
                continue
            mes_addresses[pid] = (pub_ip, port)
    assert all([node is not None for node in mes_addresses])

    threads = []

    id = 2
    k = 3
    b = [None] * (n + 10)

    for i in range(n):
        b[i] = tx_generator(250)

    timelog = write_time_log()
    i_time = time.time()
    if k == 1:
        # Attribute encryption
        for i in range(n):
            m = b[i].encode()
            _Attribute(i, id, m)
            id += 1
    elif k == 2:
        # Broadcast encryption
        for i in range(n):
            m = b[i].encode()
            _Broadcast(i, id, m)
            id += 1
    else:
        # Threshold encryption
        for i in range(n):
            m = b[i].encode()
            _Threshold(i, id, m)
            id += 1

    for thread in threads:
        thread.join()

    e_time = time.time()
    timelog.info('The encryption time of ' + str(n) +
                 ' data is ' + str((e_time - i_time)))
    print(str((e_time - i_time)))
    input("按 Enter 键继续...")
    threads = []
    i_time = time.time()

    for i in range(n):
        j = i % N
        addresse = mes_addresses[j]
        host = addresse[0]
        port = addresse[1]
        # Client_send(host, port, txs[i])
        thread = threading.Thread(
            target=Client_send, args=(host, port, txs[i], ))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    e_time = time.time()
    timelog.info(str(n) + ' pieces of data are sent in ' +
                 str(e_time - i_time))
    print(str(e_time - i_time))


if __name__ == '__main__':
    main()
