from gevent import monkey; monkey.patch_all(thread=False)

import time
import random
import traceback
from typing import List, Callable
from gevent import Greenlet
from myexperiements.sockettest.dumbo_node import DumboBFTNode
from network.socket_server import NetworkServer
from network.socket_client import NetworkClient
from multiprocessing import Value as mpValue, Queue as mpQueue
from ctypes import c_bool
from myexperiements.sockettest.Server_receipt import MesServer
import threading



def instantiate_bft_node(sid, i, B, N, f, K, S, T, bft_from_server: Callable, bft_to_client: Callable, message_get: Callable, ready: mpValue, _start: mpValue, stop: mpValue, protocol="mule", mute=False, F=100, debug=False, omitfast=False, bft_running: mpValue=mpValue(c_bool, False)):
    bft = None
    if protocol == 'dumbo':
        bft = DumboBFTNode(sid, i, B, N, f, bft_from_server, bft_to_client, message_get, ready, _start, stop, K, mute=mute, debug=debug, bft_running=bft_running)
    return bft

if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--sid', metavar='sid', required=True,
                        help='identifier of node', type=str)
    parser.add_argument('--id', metavar='id', required=True,
                        help='identifier of node', type=int)
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='f', required=True,
                        help='number of faulties', type=int)
    parser.add_argument('--B', metavar='B', required=True,
                        help='size of batch', type=int)
    parser.add_argument('--K', metavar='K', required=True,
                        help='rounds to execute', type=int)
    parser.add_argument('--S', metavar='S', required=False,
                        help='slots to execute', type=int, default=50)
    parser.add_argument('--T', metavar='T', required=False,
                        help='fast path timeout', type=float, default=1)
    parser.add_argument('--P', metavar='P', required=False,
                        help='protocol to execute', type=str, default="mule")
    parser.add_argument('--M', metavar='M', required=False,
                        help='whether to mute a third of nodes', type=bool, default=False)
    parser.add_argument('--F', metavar='F', required=False,
                        help='batch size of fallback path', type=int, default=100)
    parser.add_argument('--D', metavar='D', required=False,
                        help='whether to debug mode', type=bool, default=False)
    parser.add_argument('--O', metavar='O', required=False,
                        help='whether to omit the fast path', type=bool, default=False)
    args = parser.parse_args()

    # Some parameters
    sid = args.sid
    i = args.id
    N = args.N
    f = args.f
    B = args.B
    K = args.K
    S = args.S
    T = args.T
    P = args.P
    M = args.M
    F = args.F
    D = args.D
    O = args.O

    # Random generator
    rnd = random.Random(sid)

    # Nodes list
    addresses = [None] * N
    try:
        with open('hosts.config', 'r') as hosts:
            for line in hosts:
                params = line.split()
                pid = int(params[0])
                priv_ip = params[1]
                pub_ip = params[2]
                port = int(params[3])
                # print(pid, priv_ip ,pub_ip ,port)
                if pid not in range(N):
                    continue
                if pid == i:
                    my_address = (priv_ip, port)
                addresses[pid] = (pub_ip, port)
        assert all([node is not None for node in addresses])
        print("hosts.config is correctly read")
        
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
                if pid == i:
                    mes_address = (priv_ip, port)
                mes_addresses[pid] = (pub_ip, port)
        assert all([node is not None for node in mes_addresses])

        
        message_q = mpQueue()
        message_get = lambda: message_q.get(timeout=0.00001)
        message_put = message_q.put_nowait
        mes_ready = mpValue(c_bool, False)
        
        # bft_from_server, server_to_bft = mpPipe(duplex=True)
        # client_from_bft, bft_to_client = mpPipe(duplex=True)

        client_bft_mpq = mpQueue()
        #client_from_bft = client_bft_mpq.get
        client_from_bft = lambda: client_bft_mpq.get(timeout=0.00001)
        bft_to_client = client_bft_mpq.put_nowait

        server_bft_mpq = mpQueue()
        #bft_from_server = server_bft_mpq.get
        bft_from_server = lambda: server_bft_mpq.get(timeout=0.00001)
        server_to_bft = server_bft_mpq.put_nowait

        client_ready = mpValue(c_bool, False)
        server_ready = mpValue(c_bool, False)
        net_ready = mpValue(c_bool, False)
        stop = mpValue(c_bool, False)
        _start = mpValue(c_bool, False)
        bft_running = mpValue(c_bool, False)  # True = good network; False = bad network
        
        
        
        
        mes_server = MesServer(mes_address[1], mes_address[0], i, mes_addresses, message_put, message_get, mes_ready, stop)
        mes_server.start()
        
        net_server = NetworkServer(my_address[1], my_address[0], i, addresses, server_to_bft, server_ready, _start, stop)
        net_client = NetworkClient(my_address[1], my_address[0], i, addresses, client_from_bft, client_ready, stop, bft_running, dynamic=False)
        bft = instantiate_bft_node(sid, i, B, N, f, K, S, T, bft_from_server, bft_to_client, message_get, net_ready, _start, stop, P, M, F, D, O, bft_running)
        
        #print(O)
        
        net_server.start()
        net_client.start()
        
        
        while not client_ready.value or not server_ready.value:
            time.sleep(1)
            print("waiting for network ready...")


        with net_ready.get_lock():
            net_ready.value = True

        bft_thread = Greenlet(bft.run)
        bft_thread.start()
        bft_thread.join()

        with stop.get_lock():
            stop.value = True

        net_client.terminate()
        net_client.join()
        time.sleep(1)
        net_server.terminate()
        net_server.join()
        
        mes_server.terminate()
        mes_server.join()
        
        print("End run")

    except FileNotFoundError or AssertionError as e:
        traceback.print_exc()
