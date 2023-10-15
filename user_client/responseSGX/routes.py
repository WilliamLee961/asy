import requests
from Crypto.PublicKey import RSA
from flask import Flask, request, jsonify, json
from responseSGX.rsa.rsa_main import rsa_decrypt
from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.pairinggroup import PairingGroup, GT


def index(tyke, sec_ACL, cACL):
    global f
    cACL = cACL.encode("ISO-8859-1")
    if tyke != 0:
        private_key = rsa_keygen()
        ACL = rsa_decrypt(private_key, cACL)
        if tyke == 2:
            ACL = list(map(int, ACL.split(', ')))
            f = False
            for i in ACL:
                if i == sec_ACL:
                    f = True
        elif tyke == 4:
            f = abe(sec_ACL, ACL)
        elif tyke == 6:
            f = True
    else:
        print("1-File retrieval failure")
    return f


def rsa_keygen():
    with open('./responseSGX/rsa/SK.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key


def abe(sac_ACE, ACE):
    pairing_group = PairingGroup('MNT224')
    cpabe = AC17CPABE(pairing_group, 2)
    (pk, msk) = cpabe.setup()
    key = cpabe.keygen(pk, msk, sac_ACE)
    msg = pairing_group.random(GT)
    ctxt = cpabe.encrypt(pk, msg, ACE)
    rec_msg = cpabe.decrypt(pk, ctxt, key)
    if rec_msg == msg:
        return True
    else:
        return False

