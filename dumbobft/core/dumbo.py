
from struct_package.unpack_struct import _unpack, tyke_2, tyke_4, tyke_6
import time
import traceback
from dumbobft.core._leveldb import _write, _read
import threading
from multiprocessing import Value as mpValue, Queue as mpQueue
from io import BytesIO
import struct
from collections import deque
from dumbobft.core._leveldb import *
from honeybadgerbft.exceptions import UnknownTagError
from honeybadgerbft.core.honeybadger_block import honeybadger_block
from dumbobft.core.validators import prbc_validate
from dumbobft.core.validatedcommonsubset import validatedcommonsubset
from dumbobft.core.provablereliablebroadcast import provablereliablebroadcast
from dumbobft.core.dumbocommonsubset import dumbocommonsubset
from gevent.queue import Queue
from gevent import Greenlet
from enum import Enum
from collections import namedtuple
import socket
import numpy as np
import gevent
import os
import logging
import json
from gevent import monkey

from crypto.threshold._threshold import share_i
from struct_package.pack_struct import db_pake

monkey.patch_all(thread=False)
dbti = 0

def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-" + str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + \
        '/log/' + "consensus-node-" + str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    logger.addHandler(file_handler)
    return logger


def consensus_time_log(id: int):
    logger = logging.getLogger("consensus_time-" + str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + \
        '/log/' + "consensus_time-" + str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    logger.addHandler(file_handler)
    return logger


def db_time_log():
    logger = logging.getLogger("db_time-")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "db_time-.log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    logger.addHandler(file_handler)
    return logger


class BroadcastTag(Enum):
    ACS_PRBC = 'ACS_PRBC'
    ACS_VACS = 'ACS_VACS'
    TPKE = 'TPKE'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ACS_PRBC', 'ACS_VACS', 'TPKE'))


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        # gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]

        if tag == BroadcastTag.ACS_PRBC.value:
            recv_queue = recv_queue[j]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


class Dumbo():
    """Dumbo object used to run the protocol.

    :param str sid: The base name of the common coin that will be used to
        derive a nonce to uniquely identify the coin.
    :param int pid: Node id.
    :param int B: Batch size of transactions.
    :param int N: Number of nodes in the network.
    :param int f: Number of faulty nodes that can be tolerated.
    :param TBLSPublicKey sPK: Public key of the (f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param TBLSPrivateKey sSK: Signing key of the (f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param TBLSPublicKey sPK1: Public key of the (N-f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param TBLSPrivateKey sSK1: Signing key of the (N-f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param list sPK2s: Public key(s) of ECDSA signature for all N parties.
    :param PrivateKey sSK2: Signing key of ECDSA signature.
    :param str ePK: Public key of the threshold encryption
        (:math:`\mathsf{TPKE}`) scheme.
    :param str eSK: Signing key of the threshold encryption
        (:math:`\mathsf{TPKE}`) scheme.
    :param send:
    :param recv:
    :param K: a test parameter to specify break out after K rounds
    """

    def __init__(self, sid, pid, B, N, f, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, ePK, eSK, send, recv, message_get, _start,
                 K=3, mute=False, debug=False):
        self.sid = sid
        self.id = pid
        self.B = B
        self.N = N
        self.f = f
        self.sPK = sPK
        self.sSK = sSK
        self.sPK1 = sPK1
        self.sSK1 = sSK1
        self.sPK2s = sPK2s
        self.sSK2 = sSK2
        self.ePK = ePK
        self.eSK = eSK
        self._send = send
        self._recv = recv
        self.logger = set_consensus_log(pid)
        self.timelog = consensus_time_log(pid)
        self.round = 0  # Current block number
        self.transaction_buffer = Queue()
        self.transaction_buffer_dq = deque()
        self._per_round_recv = {}  # Buffer of incoming messages

        # self._tx = []
        self.chain_q = mpQueue()
        self.chain_put = self.chain_q.put_nowait
        self.chain_get = lambda: self.chain_q.get(timeout=0.00001)

        self.db_q = mpQueue()
        self.db_put = self.db_q.put_nowait
        self.db_get = lambda: self.db_q.get(timeout=0.00001)

        self.message_get = message_get
        self._start = _start
        self.K = K

        self.s_time = 0
        self.e_time = 0
        self.txcnt = 0
        self.txcn = 0
        self.sum_time = 0
        self.mute = mute
        self.debug = debug

    def run_bft(self):
        """Run the Dumbo protocol."""
        if self.mute:
            muted_nodes = [each * 3 +
                           1 for each in range(int((self.N - 1) / 3))]
            if self.id in muted_nodes:
                # T = 0.00001
                while True:
                    time.sleep(10)

        def get_len(msg):
            buf = BytesIO()
            buf.write(struct.pack("<i", len(msg)))
            buf.write(msg)
            buf.seek(0)
            return buf.read()

        def Client_send_db(tx):
            try:
                host = '127.0.0.1'
                port = 60000
                sk = socket.socket()
                sk.connect((host, port))
                _tx = get_len(tx)
                sk.sendall(_tx)
                sk.close()
            except Exception as e:
                print("Client_send_db ", e)

        def db_client():
            a = 0
            #db_log = db_time_log()
            dbtime = 0
            while True:
                try:
                    if self.db_q:
                        dbs_time = time.time()
                        (i, key, m) = self.db_get()
                        if m == 2:
                            cm = _read(i, key)
                            tx = db_pake(m, key, cm)
                            thread = threading.Thread(
                                target=Client_send_db, args=(tx,))
                            thread.start()
                        elif m == 4:
                            cm = _read(i, key)
                            tx = db_pake(m, key, cm)
                            thread = threading.Thread(
                                target=Client_send_db, args=(tx,))
                            thread.start()
                        elif m == 6:
                            cm = _read(i, key)
                            share = share_i(i, cm)
                            tx = db_pake(m, key, share)
                            thread = threading.Thread(
                                target=Client_send_db, args=(tx,))
                            thread.start()
                        else:
                            _write(i, key, m)
                        a += 1
                        dbe_time = time.time()
                        dbtime += dbe_time-dbs_time
                        if a == self.K:
                            print("db3-time---",str(dbtime))
                            self.timelog.info(str(a)+'---'+str(dbtime))
                    else:
                        time.sleep(0.1)
                        continue
                except Exception as e:
                    time.sleep(0.1)
                    continue

        def Client_send_chain(tx):
            try:
                host = '127.0.0.1'
                port = 50000
                sk = socket.socket()
                sk.connect((host, port))
                _tx = get_len(tx)
                sk.sendall(_tx)
                sk.close()
            except Exception as e:
                print("Client_send_chain ", e)

        def chain_client():

            while True:
                try:
                    if self.chain_q:
                        tx = self.chain_get()
                        thread = threading.Thread(
                            target=Client_send_chain, args=(tx,))
                        thread.start()
                    else:
                        time.sleep(0.1)
                        continue
                except:
                    time.sleep(0.1)
                    continue

        def submit_tx():
            while True:
                try:
                    tx = self.message_get()
                    # self.transaction_buffer.put_nowait(tx.decode())
                    _tx = tx.decode("ISO-8859-1")
                    self.transaction_buffer_dq.append(_tx)
                except:
                    time.sleep(0.1)
                    continue

        def _recv_loop():
            """Receive messages."""
            # print("start recv loop...")
            while True:
                # gevent.sleep(0)
                try:
                    (sender, (r, msg)) = self._recv()
                    # self.logger.info('recv1' + str((sender, o)))
                    # print('recv1' + str((sender, o)))
                    # Maintain an *unbounded* recv queue for each epoch
                    if r not in self._per_round_recv:
                        self._per_round_recv[r] = Queue()
                    # Buffer this message
                    self._per_round_recv[r].put_nowait((sender, msg))
                except:
                    continue

        # self._recv_thread = gevent.spawn(_recv_loop)
        self._recv_thread = Greenlet(_recv_loop)
        self._recv_thread.start()

        self.chain_client = Greenlet(chain_client)
        self.chain_client.start()

        db_thread = threading.Thread(target=db_client, args=())
        db_thread.start()

        self.message_tx = Greenlet(submit_tx)
        self.message_tx.start()

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' %
                             self.id + str(self.s_time))

        print('Node %d starts Dumbo BFT consensus' % self.id)

        while True:

            # For each round...
            # gevent.sleep(0)

            # Select B transactions (TODO: actual random selection)
            tx_to_send = []

            # while self.transaction_buffer.empty():
            while not self.transaction_buffer_dq:
                # continue
                time.sleep(0.1)
                if self._start.value:
                    time.sleep(0.1)
                    break

                    # self.transaction_buffer.put_nowait(" ")

            start = time.time()

            r = self.round
            if r not in self._per_round_recv:
                self._per_round_recv[r] = Queue()

            for b in range(self.B):
                # if self.transaction_buffer.empty():
                if not self.transaction_buffer_dq:
                    break
                else:
                    # tx_to_send.append(self.transaction_buffer.get_nowait())
                    tx_to_send.append(self.transaction_buffer_dq.popleft())

            # print("tx_to_send---",tx_to_send)

            def _make_send(r):
                def _send(j, o):
                    self._send(j, (r, o))

                return _send

            # print("r---",r)
            send_r = _make_send(r)
            recv_r = self._per_round_recv[r].get
            new_tx = self._run_round(r, tx_to_send, send_r, recv_r)
            f_tx = False

            for _tx in new_tx:
                if _tx in tx_to_send:
                    f_tx = True
                tx = _tx.encode("ISO-8859-1")
                thread = threading.Thread(target=_unpack, args=(
                    self.id, tx, self.chain_put, self.db_put,))
                thread.start()
                self.txcn += 1

            if not f_tx and tx_to_send:
                for _tx in tx_to_send:
                    # self.transaction_buffer.put_nowait(_tx)
                    self.transaction_buffer_dq.appendleft(_tx)

            if self.logger != None:
                tx_cnt = str(new_tx).count("")
                self.txcnt += tx_cnt
                self.logger.info('Node %d Delivers ACS Block in Round %d with having %d TXs' % (
                    self.id, r, tx_cnt))
                end = time.time()
                self.logger.info('ACS Block Delay at Node %d: ' %
                                 self.id + str(end - start))
                self.logger.info('Current Block\'s TPS at Node %d: ' %
                                 self.id + str(tx_cnt / (end - start)))
                self.sum_time += end - start
                
                print(self.txcn, " data consensus is complete")
            # print('* Node %d outputs an ACS Block at the %d-th Round:' % (self.id, r))
            # print("    - Latency of this block: %.12f seconds" % (end - start))
            # print("    - Throughput of this block: %.9f tps" % (tx_cnt / (end - start)))

            # Put undelivered but committed TXs back to the backlog buffer
            # for _tx in tx_to_send:
            #    if _tx not in new_tx:
            #        self.transaction_buffer.put_nowait(_tx)

            # print('buffer at %d:' % self.id, self.transaction_buffer)
            # if self.logger != None:
            #    self.logger.info('Backlog Buffer at Node %d:' % self.id + str(self.transaction_buffer))
            self._start.value = False
            self.round += 1  # Increment the round
            #if self.round >= self.K:
                #break  # Only run one round for now

            if self.txcn >= self.K:
                self.timelog.info('The consensus run time of Round ' + str(r) + ' is ' + str(
                    end - start) + ' and the total run time is ' + str(self.sum_time) + '. ' + str(
                    self.txcn) + ' data consensus is complete.')
                print( str(self.txcn),"---BFT-time---",str(self.sum_time))
                break


        self._recv_thread.join()
        self.chain_client.join()
        db_thread.join()
        self.message_tx.join()
        print("END")
        if self.logger != None:
            self.e_time = time.time()
            self.logger.info("node %d breaks in %f seconds with total delivered Txs %d" % (
                self.id, self.e_time - self.s_time, self.txcnt))
        else:
            print("node %d breaks" % self.id)

        # print("*******************************************")
        # print('* Node %d breaks the test' % self.id )
        # print("    - Average latency: %.12f seconds" % ((self.e_time-self.s_time) / self.K) )
        # print("    - Average throughput: %.9f tps" % (tx_cnt * self.K  / ((self.e_time-self.s_time))))

        # self._recv_thread.join(timeout=2)

    #
    def _run_round(self, r, tx_to_send, send, recv):
        """Run one protocol round.
        :param int r: round id
        :param tx_to_send: Transaction(s) to process.
        :param send:
        :param recv:
        """

        # Unique sid for each round
        sid = self.sid + ':' + str(r)
        pid = self.id
        N = self.N
        f = self.f

        prbc_recvs = [Queue() for _ in range(N)]
        vacs_recv = Queue()
        tpke_recv = Queue()

        my_prbc_input = Queue(1)

        prbc_outputs = [Queue(1) for _ in range(N)]
        prbc_proofs = dict()

        vacs_input = Queue(1)
        vacs_output = Queue(1)

        recv_queues = BroadcastReceiverQueues(
            ACS_PRBC=prbc_recvs,
            ACS_VACS=vacs_recv,
            TPKE=tpke_recv,
        )

        bc_recv_loop_thread = Greenlet(
            broadcast_receiver_loop, recv, recv_queues)
        bc_recv_loop_thread.start()

        # print(pid, r, 'tx_to_send:', tx_to_send)
        # if self.logger != None:
        #    self.logger.info('Commit tx at Node %d:' % self.id + str(tx_to_send))

        def _setup_prbc(j):
            """Setup the sub protocols RBC, BA and common coin.
            :param int j: Node index for which the setup is being done.
            """

            def prbc_send(k, o):
                """Reliable send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                send(k, ('ACS_PRBC', j, o))

            # Only leader gets input
            # print("my_prbc_input222---",my_prbc_input)
            prbc_input = my_prbc_input.get if j == pid else None
            # print("prbc_input---",prbc_input)
            if self.debug:
                prbc_thread = gevent.spawn(provablereliablebroadcast, sid + 'PRBC' + str(r) + str(j), pid, N, f,
                                           self.sPK2s, self.sSK2, j,
                                           prbc_input, prbc_recvs[j].get, prbc_send, self.logger)
            else:
                prbc_thread = gevent.spawn(provablereliablebroadcast, sid + 'PRBC' + str(r) + str(j), pid, N, f,
                                           self.sPK2s, self.sSK2, j,
                                           prbc_input, prbc_recvs[j].get, prbc_send)

            def wait_for_prbc_output():
                value, proof = prbc_thread.get()
                prbc_proofs[sid + 'PRBC' + str(r) + str(j)] = proof
                prbc_outputs[j].put_nowait((value, proof))

            gevent.spawn(wait_for_prbc_output)

        def _setup_vacs():

            def vacs_send(k, o):
                """Threshold encryption broadcast."""
                """Threshold encryption broadcast."""
                send(k, ('ACS_VACS', '', o))

            def vacs_predicate(j, vj):
                prbc_sid = sid + 'PRBC' + str(r) + str(j)
                try:
                    proof = vj
                    if prbc_sid in prbc_proofs.keys():
                        try:
                            _prbc_sid, _roothash, _ = proof
                            assert prbc_sid == _prbc_sid
                            _, roothash, _ = prbc_proofs[prbc_sid]
                            assert roothash == _roothash
                            return True
                        except AssertionError:
                            print("1 Failed to verify proof for PB")
                            return False
                    else:
                        assert prbc_validate(prbc_sid, N, f, self.sPK2s, proof)
                        prbc_proofs[prbc_sid] = proof
                        return True
                except AssertionError:
                    print("2 Failed to verify proof for PB")
                    return False

            if self.debug:
                vacs_thread = Greenlet(validatedcommonsubset, sid + 'VACS' + str(r), pid, N, f,
                                       self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2,
                                       vacs_input.get, vacs_output.put_nowait,
                                       vacs_recv.get, vacs_send, vacs_predicate, self.logger)
            else:
                vacs_thread = Greenlet(validatedcommonsubset, sid + 'VACS' + str(r), pid, N, f,
                                       self.sPK, self.sSK, self.sPK1, self.sSK1, self.sPK2s, self.sSK2,
                                       vacs_input.get, vacs_output.put_nowait,
                                       vacs_recv.get, vacs_send, vacs_predicate)
            vacs_thread.start()

        # N instances of PRBC
        for j in range(N):
            # print("start to set up RBC %d" % j)
            _setup_prbc(j)

        # One instance of (validated) ACS
        # print("start to set up VACS")
        _setup_vacs()

        # One instance of TPKE
        def tpke_bcast(o):
            """Threshold encryption broadcast."""
            send(-1, ('TPKE', '', o))

        # One instance of ACS pid, N, f, prbc_out, vacs_in, vacs_out
        dumboacs_thread = Greenlet(dumbocommonsubset, pid, N, f, [prbc_output.get for prbc_output in prbc_outputs],
                                   vacs_input.put_nowait,
                                   vacs_output.get)

        dumboacs_thread.start()
        # print("tx_to_send222---",str(tx_to_send))
        # print("my_prbc_input111---",my_prbc_input)
        _output = honeybadger_block(pid, self.N, self.f, self.ePK, self.eSK,
                                    propose=json.dumps(tx_to_send),
                                    acs_put_in=my_prbc_input.put_nowait, acs_get_out=dumboacs_thread.get,
                                    tpke_bcast=tpke_bcast, tpke_recv=tpke_recv.get)

        block = set()
        for batch in _output:
            decoded_batch = json.loads(batch.decode())
            for tx in decoded_batch:
                block.add(tx)

        bc_recv_loop_thread.kill()

        return list(block)

    # TODO： make help and callhelp threads to handle the rare cases when vacs (vaba) returns None
