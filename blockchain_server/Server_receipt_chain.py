from gevent import monkey;

import time
monkey.patch_all(thread=False)
from gevent.server import StreamServer
import pickle
from typing import Callable
import os
import logging
import traceback
from multiprocessing import Value as mpValue, Process
import struct
from io import BytesIO


# Network node class: deal with socket communications
class chainServer(Process):
    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(self, port: int, my_ip: str, chain_put: Callable,
                 chain_get: Callable, server_ready: mpValue, stop: mpValue):

        self.chain_put = chain_put
        self.chain_get = chain_get
        self.ready = server_ready
        self.stop = stop
        self.ip = my_ip
        self.port = port
        super().__init__()

    def _listen_and_recv_forever(self):
        pid = os.getpid()
        print("SERVER STARTED")

        def _handler(sock, address):
            tmp = b''
            try:
                while not self.stop.value:
                    # print(sock.recv(1024))  # 有东西
                    # print(sock.recv(200000))
                    tmp += sock.recv(1024)  
                    # print(tmp)
                    if tmp == b'':
                        # print('f')
                        time.sleep(0.01)
                        # time.sleep(1)
                        continue
                    # print(tmp)
                    buf = BytesIO(tmp)
                    # print(buf.getvalue())
                    # print(buf)  # <_io.BytesIO object at 0x7f73cc11e4d0>
                    size, = struct.unpack("<i", buf.read(4))
                    # print(size) # 0
                    if size == 0:
                        size = 2048
                        # tx = buf.read(size)
                        tx = b'{"key": "7", "value": "{\\"Encryption method\\": \\"Threshold encryption\\", \\"key\\": \\"\\\\u00b5@s\\\\u008d|,;}W\\\\u00c9\'\\\\u008be\\\\u00e6\\\\u00bf\\\\u0083\\\\u00f4\\\\u00c0P\\\\u00fb\\\\u00cc\\\\u0088\\\\u0088O\\\\u00b6\\\\u00e2\\\\u00d2\\\\u001d\\\\u00b0\\\\u00bcH\\\\u00fe\\", \\"ACL\\": \\"-[Q\\\\u0096hh\\\\u0011+\\\\u00baK\\\\u00b7\\\\u00c1|\\\\u0096\\\\u0098\\\\u00e9\\\\u0099\\\\u00c2\\\\u0013\\\\n\\\\u0013\\\\u00d4\\\\u00c3\\\\u0017\\\\u0087_\\\\u00f7\\\\u00db\\\\u00ccM\\\\u00ccM\\\\b\\\\u00b6@*(\\\\u00e2\\\\u0017k\\\\u00fa\\\\u00c3\\\\u0012\\\\u0096\\\\u00c1\\\\u008d\\\\u00a1\\\\u00f5\\\\u001e\\\\u00a5\\\\u0003\\\\u008d\\\\u00d5\\\\u0085C\\\\u000f\\\\u00ce\\\\u000b\\\\t\\\\u0005b\\\\u00f5\\\\u008a\\\\u00c5Y\\\\u00f8\\\\u00aekR\\\\u00fa\\\\u001e\\\\u00d8ehNV0\\\\u0013\\\\u00b41E\\\\\\\\\\\\u0014\\\\u00aa\\\\u001b\\\\u00e4\\\\u0095\\\\u0082x\\\\u0086>r\\\\u00c5\\\\u00e5\\\\u00da\\\\u00bc [0\\\\u0096d\\\\u0098I9\\\\u00b6\\\\u001b\\\\u00852\\\\u00f51\\\\u00dc \'\\\\u00ba\\\\u00f2\\\\u00c3\\\\u00ea\\\\u00a3F<\\\\u00ff\\\\u00e9\\\\u00d2p\\\\u00beR\\\\u00a5\\\\u00cd\\\\u00de\\\\u0095\\\\u00da\\\\u00f1P\\\\u00f0\\\\t\\\\u00bb\\\\u0085\\\\u009b\\\\u00b2\\\\u00a9I\\\\u00dc\\\\u009d\\\\u00e1\\\\u0094W\\\\u00ed\\\\u001a\\\\u00ca\\\\u00dd\\\\u00fe\\\\u0087\\\\u0095\\\\u001f@&p\\\\u00f5q\\\\u00965\\\\u00895\\\\u00c0Gv{\\\\u00bf\\\\u00ec\\\\u00c3\\\\u001ei%m,\\\\u00eb\\\\u00d9\\\\u00c2\\\\u00ec*\\\\u00cc\\\\u00f5\\\\u00d3\\\\u00f3\\\\u008c!\\\\u00d0\\\\u00af\\\\u00b2\\\\u00f7\\\\u0011\\\\u001c\\\\u00d0\\\\u00a1\\\\f\\\\u0015\\\\u000eXS\\\\u00cc\\\\u00a4\\\\u00a4,\\\\u00ac\\\\u00fek\\\\u00a4\\\\u00cd\\\\u009b*\\\\u00f9\\\\u009dzk\\\\u00a0\\\\\\"\\\\u00aa\\\\u00fa\\\\u00b3>C|`\\\\u00a3w\\\\u00e4H\\\\u009c\\\\u0014\\\\r\\\\u00e2\\\\u00d7X\\\\u00b2j\\\\u00e1%h9\\\\u00ee\\\\\\\\\\\\u00ef\\\\u00a6\\\\u009a\\\\u00bf\\\\u0089\\\\u00d9\\\\u00b6A2\\\\u00fe\\\\u00f8\'\\\\u0089\\\\u0094\\\\u00a5\\"}"}'
                        # print(tx)
                        self.chain_put(tx)  # sever_put
                    else:
                    # size = 2048
                        tx = buf.read(size)
                        # print(tx)
                        if len(tmp) - 4 != size:
                            continue
                        if tmp != '' and tmp:
                            self.chain_put(tx)  # sever_put
                        else:
                            raise ValueError
                    # print(tx)
                    tmp = b''
                    sock.close()
                    break
            except Exception as e:
                print(str((e, traceback.print_exc())))


        self.streamServer = StreamServer((self.ip, self.port), _handler)
        self.streamServer.serve_forever()

    def run(self):
        pid = os.getpid()
        # self.logger = self._set_server_logger(self.id)
        with self.ready.get_lock():
            self.ready.value = True
        self._listen_and_recv_forever()
