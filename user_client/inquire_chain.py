import socket
import hashlib
import struct
import time
from io import BytesIO
import json
import logging
import os
import threading
import requests
from flask import json
from struct_package.pack_struct import _pack
from crypto.broadcast.generateBroadcastkeys import Broadcast_encryption, Broadcast_decryption
from crypto.ABE1.att_encrypt import *
from crypto.ABE1.att_decrypt import decrypt
from struct_package.unpack_struct import broadcast_uppack, attribute_unpack
from responseSGX.routes import index

id = 2
n = 10

txs = [None] * (n + 10)
bufs = [None] * (n + 10)

def inquire_time_log():
    logger = logging.getLogger("inquire_time")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "inquire_time" + ".log"
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
        print("YES")
        sk.close()
    except:
        print("NO")


def _tyke(tyke_str):
    if tyke_str == "Broadcast encryption":
        return 2
    elif tyke_str == "Attribute encryption":
        return 4
    elif tyke_str == "Threshold encryption":
        return 6


def broadcast_keygen(sec_ACL):
    filename = "./config/broadenckeys/%d.keys" % sec_ACL
    secret_information_list = pickle.loads(open(filename, 'rb').read())
    open(filename, 'r').close()
    filename = "./config/AESCBCIV.keys"
    IV = pickle.loads(open(filename, 'rb').read())
    open(filename, 'r').close()
    return secret_information_list, IV


def attribute_keygen():
    return out_key()


def sgx(tyke, sec_ACL, cACL):
    try:
        url = 'http://39.105.219.78:8000/sgx'
        data = {'tyke': tyke, 'sec_ACL': sec_ACL, 'cACL': cACL}
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=json.dumps(data), headers=headers)
        data = response.json()
        print("Access SGX successfully")
        return data["Flag"]
    except:
        print("Unable to access SGX===")
        response = index(tyke, sec_ACL, cACL)
        return response
        return False


def hm_encrypt(tyke, chm_b, cACL):
    if tyke == 2:
        sec_ACL = 3
        f = sgx(tyke, sec_ACL, cACL)
        if f:
            chm = broadcast_uppack(chm_b)
            secret_information_list, IV = broadcast_keygen(sec_ACL)
            hm = Broadcast_decryption(secret_information_list, IV, chm)
            buf = _pack(tyke, "".encode(), hm, "".encode())
            return buf
        else:
            return ""
    elif tyke == 4:
        sec_ACL = ['ONE', 'TWO', 'THREE']
        f = sgx(tyke, sec_ACL, cACL)
        if f:
            chm = attribute_unpack(chm_b)
            (pk, msk) = attribute_keygen()
            hm = decrypt(pk, msk, sec_ACL, chm)
            buf = _pack(tyke, "".encode(), hm, "".encode())
            return buf
        else:
            return ""
    elif tyke == 6:
        sec_ACL = 'label'
        f = sgx(tyke, sec_ACL, cACL)
        if f:
            chm = chm_b
            hm = chm
            buf = _pack(tyke, "".encode(), hm, "".encode())
            return buf
        else:
            return ""
    else:
        return ""


def query_chain(id, i):
    key_chain = str(id)
    print("=========== 根据HASH查询：", key_chain, " ===========")
    response = requests.get(url='http://119.29.232.209:9090/fabric/getData', params={"key": key_chain})
    fileDict = json.loads(response.content.decode('utf-8'))
    try:
        fileMetaData = json.loads(fileDict["value"])
        if fileDict['code'] != 200:
            print("0-File retrieval failure")
        else:
            print(fileMetaData['Encryption method'])
            tyke = _tyke(fileMetaData['Encryption method'])
            cACL = fileMetaData["ACL"]
            chm_b = fileMetaData['key'].encode("ISO-8859-1")
            txs[i] = {"tyke": tyke, "cACL": cACL, "chm_b": chm_b}
    except Exception as e:
        print(e)
        print("2-File retrieval failure")


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

    timelog = inquire_time_log()
    i_time = time.time()
    cn = 0
    for i in range(n):
        thread = threading.Thread(target=query_chain, args=(id, i,))
        threads.append(thread)
        thread.start()
        cn += 1

    for thread in threads:
        thread.join()

    for i in range(n):
        if txs[i] is None or txs[i] == "":
            cn -= 1
            print(i, " Unable to access")

    e_time = time.time()
    print("chain--- ", str(cn), " --- ", str(e_time - i_time))
    timelog.info('chain--- ' + str(cn) + ' --- ' + str(e_time - i_time))

    i_time = time.time()

    for i in range(n):
        if txs[i] is None or txs[i] == "":
            bufs[i] = ""
        else:
            tx = txs[i]
            tyke = tx["tyke"]
            cACL = tx["cACL"]
            chm_b = tx["chm_b"]
            bufs[i] = hm_encrypt(tyke, chm_b, cACL)

    e_time = time.time()
    print('sgx ', str(cn), ' --- ', str(e_time - i_time))
    timelog.info('sgx ' + str(cn) + ' --- ' + str(e_time - i_time))

    input("按 Enter 键继续...")

    threads = []
    i_time = time.time()

    cn = 0
    for i in range(n):
        j = i % N
        addresse = mes_addresses[j]
        host = addresse[0]
        port = addresse[1]
        if bufs[i] != '':
            thread = threading.Thread(target=Client_send, args=(host, port, bufs[i],))
            threads.append(thread)
            thread.start()
            cn += 1

    for thread in threads:
        thread.join()

    e_time = time.time()
    print("--- ", str(e_time - i_time))
    timelog.info('The time for a user to inquire ' + str(n) + ' data is ' + str(e_time - i_time))


if __name__ == '__main__':
    main()
