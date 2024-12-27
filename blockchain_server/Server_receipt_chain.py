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
                    tmp += sock.recv(200000)
                    if tmp == b'':
                        time.sleep(0.01)
                        continue
                    buf = BytesIO(tmp)
                    size, = struct.unpack("<i", buf.read(4))
                    tx = buf.read(size)
                    if len(tmp) - 4 != size:
                        continue
                    if tmp != '' and tmp:
                        self.chain_put(tx)  # sever_put
                    else:
                        raise ValueError
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
