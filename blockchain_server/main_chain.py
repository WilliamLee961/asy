import struct
import threading
from ctypes import c_bool
import hashlib
import time
import socket
import struct
from io import BytesIO
from Server_receipt_chain import chainServer
from multiprocessing import Value as mpValue, Queue as mpQueue
import requests
import json
from requests_toolbelt import MultipartEncoder
import logging
import os

global _time


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


def cochain(tx, cn):
    print("=========== 文件元信息上链 ===========")
    fields = json.loads(tx.decode())

    res = requests.post('http://119.29.232.209:9090/fabric/setData', data=fields)
    res = str(res) + "---" + str(cn) + "---" + str(time.time() - _time)
    timelog = chain_time_log()
    timelog.info(res)
    print(res)


def main():
    # FROM OUTSIDE TO SERVER UNTRUSTED PART
    host = ''
    port = 50000

    n = 4
    f = 1

    chain_q = mpQueue()
    chain_put = chain_q.put_nowait
    chain_get = lambda: chain_q.get(timeout=0.00001)
    chain_ready = mpValue(c_bool, False)
    stop = mpValue(c_bool, False)

    chain_server: chainServer = chainServer(port, host, chain_put, chain_get, chain_ready, stop)
    chain_server.start()
    chain_cnt = dict()
    chain_map = dict()
    st = dict()
    global _time
    timelog = chain_time_log()
    cn = 0
    threads = []

    while chain_ready:
        if not chain_q.empty():
            tx = chain_get()
            tx_h = _hash(tx)

            if tx_h not in st:
                st[tx_h] = False

            if st[tx_h]:
                chain_cnt[tx_h] = chain_cnt[tx_h] + 1
                if chain_cnt[tx_h] == n:
                    del chain_cnt[tx_h]
                    del st[tx_h]
                continue

            if tx_h not in chain_map:
                chain_map[tx_h] = tx

            if tx_h not in chain_cnt:
                chain_cnt[tx_h] = 1
            else:
                chain_cnt[tx_h] = chain_cnt[tx_h] + 1
                if chain_cnt[tx_h] >= f + 1:
                    _tx = chain_map[tx_h]
                    del chain_map[tx_h]
                    cn += 1
                    if cn == 1:
                        _time = time.time()
                    timelog.info('Article ' + str(cn) + ' Data link time is ' + str(time.time() - _time))
                    thread = threading.Thread(target=cochain, args=(_tx, cn))
                    threads.append(thread)
                    thread.start()

                    st[tx_h] = True
        else:
            time.sleep(1)
            continue

    for thread in threads:
        thread.join()

    chain_server.terminate()
    chain_server.join()


if __name__ == '__main__':
    main()


'''
# 1.获取文件Hash : Fdsaxefe0fsdfsxxx1
# 2.文件hash和元信息上链


print("=========== 文件元信息上链 ===========")
fields = {
    "key":"DxdsiRE002342xxx12345",
    # 元信息字节定义哈，可以把数据库里面存的元信息序列化到这里，也可以传一些其他东西序列化到这
    "value": '{"fileName": "文件1", "fileSize": 1024,"other": "文件其他信息"}',
}
x = {"fileName": "文件1", "fileSize": 1021,"other": "文件其他信息"}
res = requests.post('http://119.29.232.209:9090/fabric/setData',data=fields)
print(res)

# 3. 根据hash去链上查询元信息
print("=========== 根据HASH查询：DxdsiRE002342xxx12345 ===========")
response = requests.get(url='http://119.29.232.209:9090/fabric/getData', params={"key": "DxdsiRE002342xxx12345"})
print(response.content.decode('utf-8'))		# 打印状态码

fileDict = json.loads(response.content.decode('utf-8'))
fileMetaData= json.loads(fileDict["value"])
if fileDict['code'] != 200:
    print("文件获取失败")
else:
    # 拿到了文件信息，之后就可以和数据库里面的信息进行比对了
    print("--> 文件名称: ",fileMetaData['fileName'])
    print("--> 文件大小: ",fileMetaData['fileSize'])
    print("--> 文件其他信息: ",fileMetaData['other'])
'''