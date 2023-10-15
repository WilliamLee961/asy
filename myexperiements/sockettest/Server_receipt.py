from gevent import monkey; monkey.patch_all(thread=False)

from gevent.server import StreamServer
import pickle
from typing import Callable
import os
import logging
import traceback
from multiprocessing import Value as mpValue, Process
import struct
from io import BytesIO
import time


# Network node class: deal with socket communications
class MesServer (Process):

    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(self, port: int, my_ip: str, id: int, addresses_list: list, server_to_bft: Callable, message_get: Callable, server_ready: mpValue, stop: mpValue):

        self.server_to_bft = server_to_bft
        self.message_get = message_get
        self.ready = server_ready
        self.stop = stop
        self.ip = my_ip
        self.port = port
        self.id = id
        self.addresses_list = addresses_list
        self.N = len(self.addresses_list)
        self.is_in_sock_connected = [False] * self.N
        self.socks = [None for _ in self.addresses_list]
        super().__init__()

    def _listen_and_recv_forever(self):
        pid = os.getpid()
        print("receipt my IP is " + self.ip)
        def _handler(sock, address):
            #buf = b''
            
            tmp = b''
            try:
                while not self.stop.value:
                    tmp += sock.recv(10485760)
                    if tmp == b'':
                        time.sleep(0.001)
                        continue
                    buf = BytesIO(tmp)
                    size, = struct.unpack("<i", buf.read(4))
                    tx = buf.read(size)
                    if len(tmp) - 4 != size:
                        continue
                    if tmp != '' and tmp:
                        self.server_to_bft(tx)  # sever_put
                    else:
                        raise ValueError
                    tmp = b''
            except Exception as e:
                print(str((e, traceback.print_exc())))
            finally:
                sock.close()

        self.streamServer = StreamServer((self.ip, self.port), _handler)
        self.streamServer.serve_forever()


    def run(self):
        pid = os.getpid()
        #self.logger = self._set_server_logger(self.id)
        with self.ready.get_lock():
            self.ready.value = True
        self._listen_and_recv_forever()

    def _address_to_id(self, address: tuple):
        for i in range(self.N):
            if address[0] != '127.0.0.1' and address[0] == self.addresses_list[i][0]:
                return i
        return int((address[1] - 10000) / 200)

