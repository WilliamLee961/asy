import struct
import threading
from ctypes import c_bool
import hashlib
import time
import socket
import struct
from io import BytesIO
from Server_receipt_db import dbServer
from multiprocessing import Value as mpValue, Queue as mpQueue
import requests
import json
from requests_toolbelt import MultipartEncoder
import logging
import os
from crypto.threshold._threshold import share_unpack, Threshold_decryption
from unpack_struct import db_unpack
from crypto.broadcast.generateBroadcastkeys import Broadcast_decryption
from crypto.ABE1.att_decrypt import *

ress = 0


def chain_time_log():
    logger = logging.getLogger("chain_time")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "chain_time" + ".log"
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

def b_en(cm):
    mm = Broadcast_decryption(3, cm)

def a_en(cm):
    attr_list = ['ONE', 'TWO', 'THREE']
    mm = decrypt(attr_list, cm)

def t_en(S, shares, tx):
    T_key = dict((s, shares[s]) for s in S)
    _m = Threshold_decryption(tx, T_key)

def main():
    # FROM OUTSIDE TO SERVER UNTRUSTED PART
    # host = ''
    host = ''
    port = 60000
    n = 4
    f = 1
    db_q = mpQueue()
    db_put = db_q.put_nowait
    def db_get(): return db_q.get(timeout=0.00001)
    db_ready = mpValue(c_bool, False)
    stop = mpValue(c_bool, False)

    db_server: dbServer = dbServer(port, host, db_put, db_get, db_ready, stop)
    db_server.start()
    db_cnt = dict()
    db_map = dict()
    st = dict()
    _time = 0
    res = 0
    timelog = chain_time_log()
    threads = []

    while db_ready:
        if not db_q.empty():
            tx_ = db_get()
            tyke, hm, cm = db_unpack(tx_)
            tx_h = hm
            if tyke == 6:
                if tx_h not in st:
                    st[tx_h] = False

                if st[tx_h]:
                    db_cnt[tx_h] = db_cnt[tx_h] + 1
                    if db_cnt[tx_h] == n:
                        del db_cnt[tx_h]
                        del st[tx_h]
                    continue

                if tx_h not in db_map:
                    db_map[tx_h] = []
                    db_map[tx_h].append(cm)

                if tx_h not in db_cnt:
                    db_cnt[tx_h] = 1
                else:
                    db_cnt[tx_h] = db_cnt[tx_h] + 1
                    db_map[tx_h].append(cm)
                    if db_cnt[tx_h] == f + 1:
                        shares = [None] * 5
                        tx = b''
                        for cm in db_map[tx_h]:
                            i, share, _tx = share_unpack(cm)
                            tx = _tx
                            shares[i] = share
                        S = set()
                        cn = 0
                        for i in range(4):
                            if shares[i] != None and cn < 2:
                                S.add(i)
                                cn += 1
                        t1 = time.time()
                        t_en(S, shares, tx)
                        t2 = time.time()
                        _time += t2-t1
                        res += 1
                        if res == ress:
                            print(_time)
                        del db_map[tx_h]
                        st[tx_h] = True
            elif tyke == 4:
                if tx_h not in st:
                    st[tx_h] = False

                if st[tx_h]:
                    db_cnt[tx_h] = db_cnt[tx_h] + 1
                    if db_cnt[tx_h] == n:
                        del db_cnt[tx_h]
                        del st[tx_h]
                    continue

                if tx_h not in db_map:
                    db_map[tx_h] = tx

                if tx_h not in db_cnt:
                    db_cnt[tx_h] = 1
                else:
                    db_cnt[tx_h] = db_cnt[tx_h] + 1
                    if db_cnt[tx_h] >= f + 1:
                        _tx = db_map[tx_h]

                        t1 = time.time()
                        a_en(hm, _tx)
                        t2 = time.time()
                        _time += t2-t1
                        res += 1
                        if res == ress:
                            print(_time)
                        del db_map[tx_h]
                        st[tx_h] = True
            elif tyke == 2:
                if tx_h not in st:
                    st[tx_h] = False

                if st[tx_h]:
                    db_cnt[tx_h] = db_cnt[tx_h] + 1
                    if db_cnt[tx_h] == n:
                        del db_cnt[tx_h]
                        del st[tx_h]
                    continue

                if tx_h not in db_map:
                    db_map[tx_h] = tx

                if tx_h not in db_cnt:
                    db_cnt[tx_h] = 1
                else:
                    db_cnt[tx_h] = db_cnt[tx_h] + 1
                    if db_cnt[tx_h] >= f + 1:
                        _tx = db_map[tx_h]

                        t1 = time.time()
                        b_en(hm, _tx)
                        t2 = time.time()
                        _time += t2-t1
                        res += 1
                        if res == ress:
                            print(_time)
                        del db_map[tx_h]
                        st[tx_h] = True
        else:
            time.sleep(1)
            continue

    for thread in threads:
        thread.join()

    db_server.terminate()
    db_server.join()


if __name__ == '__main__':
    main()
