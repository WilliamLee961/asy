from gevent import monkey; monkey.patch_all(thread=False)

import queue
import random
from typing import  Callable
import os
import pickle
from gevent import time, Greenlet
from dumbobft.core.dumbo import Dumbo
from multiprocessing import Value as mpValue
from coincurve import PrivateKey, PublicKey
from ctypes import c_bool

def load_key(id, N):

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sPK.key', 'rb') as fp:
        sPK = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sPK1.key', 'rb') as fp:
        sPK1 = pickle.load(fp)

    sPK2s = []
    for i in range(N):
        with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sPK2-' + str(i) + '.key', 'rb') as fp:
            sPK2s.append(PublicKey(pickle.load(fp)))

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'ePK.key', 'rb') as fp:
        ePK = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sSK-' + str(id) + '.key', 'rb') as fp:
        sSK = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sSK1-' + str(id) + '.key', 'rb') as fp:
        sSK1 = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sSK2-' + str(id) + '.key', 'rb') as fp:
        sSK2 = PrivateKey(pickle.load(fp))

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'eSK-' + str(id) + '.key', 'rb') as fp:
        eSK = pickle.load(fp)

    return sPK, sPK1, sPK2s, ePK, sSK, sSK1, sSK2, eSK


class DumboBFTNode (Dumbo):

    def __init__(self, sid, id, B, N, f, bft_from_server: Callable, bft_to_client: Callable, message_get: Callable, ready: mpValue, _start: mpValue, stop: mpValue, K=3, mode='debug', mute=False, debug=False, bft_running: mpValue=mpValue(c_bool, False), tx_buffer=None):
        self.sPK, self.sPK1, self.sPK2s, self.ePK, self.sSK, self.sSK1, self.sSK2, self.eSK = load_key(id, N)
        self.bft_from_server = bft_from_server
        self.bft_to_client = bft_to_client
        self.message_get = message_get
        self.send = lambda j, o: self.bft_to_client((j, o))
        self.recv = lambda: self.bft_from_server()
        self.ready = ready
        self.stop = stop
        self.mode = mode
        self._start = _start
        #self.message = lambda: self.message_get()
        self.running = bft_running
        Dumbo.__init__(self, sid, id, B, N, f, self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2, self.ePK, self.eSK, self.send, self.recv, self.message_get, self._start, K=K, mute=mute, debug=debug)

    def run(self):

        pid = os.getpid()
        self.logger.info('node %d\'s starts to run consensus on process id %d' % (self.id, pid))

        #self.prepare_bootstrap()

        while not self.ready.value:
            time.sleep(1)

        self.running.value = True
	
        self.run_bft()
       
        self.stop.value = True
  
