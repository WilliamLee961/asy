from charm.core.engine.protocol import *
from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import prime256v1
from base64 import encodebytes, decodebytes
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Cipher import AES
from functools import reduce

# Author: Sisi Duan, Information Systems, University of Maryland Baltimore County
# http://sduan.informationsystems.umbc.edu/
# Python version >= 3

# Securing Threshold Cryptosystems against Chosen Ciphertext Attack

# Victor Shoup and Rosario Gennaro
# https://link.springer.com/article/10.1007/s00145-001-0020-9


# Dependencies: Charm, http://jhuisi.github.io/charm/, dev branch
#         a wrapper for ECGroup (Elliptic curve based crypto)

# Input message can be both string and bytes

group = ECGroup(prime256v1)

g = group.random(G)
g1 = group.random(G)

ZERO = group.init(ZR, 0)
ONE = group.init(ZR, 1)


def btog(g):
    return group.deserialize(g)


def gtob(g):
    return group.serialize(g)


def serialize(g):
    return decodebytes(group.serialize(g)[2:])


def serialize1(g):
    return group.serialize(g)


def deserialize(g):
    return group.deserialize(g)


def deserialize0(g):
    # Only work in G1 here
    return group.deserialize('0:' + encodebytes(g))


def deserialize1(g):
    # Only work in G1 here
    return group.deserialize('1:' + encodebytes(g))


def deserialize2(g):
    # Only work in G1 here
    return group.deserialize('2:' + encodebytes(g))


def hashG(g):  # H_1
    return SHA256.new(serialize1(g)).digest()


def bytestostr(m):
    return m.decode("ISO-8859-1")


def strtobytes(m):
    return m.encode("ISO-8859-1")


def hashH(x, L, u, w, u1, w1):  # H_2
    # assert len(x) == 32
    return group.hash(bytestostr(x + L + serialize1(u) + serialize1(w) + serialize1(u1) + serialize1(w1)))


def hash4(u, u1, h1):  # H_4
    return group.hash(serialize1(u) + serialize1(u1) + serialize1(h1))


def xor(x, y):
    # assert len(x) == len(y) == 32
    # if type(x) != bytes:
    #    print ("Input must be the format of bytes")
    #    return
    result = []
    for x_, y_ in zip(x, y):
        if type(x) == str:
            result.append(bytes([ord(x_) ^ y_]))
        else:
            result.append(bytes([x_ ^ y_]))
    return b''.join(result)
    '''if type(x) == bytes and type(y) == bytes:
        return ''.join(chr(x_^y_) for x_,y_ in zip(x,y))
    if type(x) == str and type(y) == bytes:
        return ''.join(chr(ord(x_)^y_) for x_,y_ in zip(x,y))
    if type(x) == bytes and type(y) == str:
        return ''.join(chr(x_^ord(y_)) for x_,y_ in zip(x,y))
    return ''.join(chr(ord(x_)^ord(y_)) for x_,y_ in zip(x,y))'''


# k -- threshold
# VK -- verification key
# VKs -- verification keys
# SK -- private keys
class TDHPublicKey:
    def __init__(self, l, k, VK, VKs):  # l: number of players, k: threshold
        self.l = l
        self.k = k
        self.VK = VK
        self.VKs = VKs
        self.g = g

    def lagrange(self, S, j):
        # Assert S is a subset of range(0,self.l)
        assert len(S) == self.k
        assert type(S) is set
        assert S.issubset(range(0, self.l))
        S = sorted(S)

        assert j in S
        assert 0 <= j < self.l

        def mul(a, b): return a * b
        num = reduce(mul, [ZERO - jj * ONE - ONE for jj in S if jj != j])
        den = reduce(mul, [j * ONE - jj * ONE for jj in S if jj != j])

        return num * (den ** (-1))

    def encrypt(self, m, L, g):
        # Only encrypt 32 byte strings
        # assert len(m) == 32
        r = group.random()
        s = group.random()
        c = xor(m, hashG(self.VK ** r))
        u = g ** r
        w = g ** s
        u1 = g1 ** r
        w1 = g1 ** s
        e = hashH(c, L, u, w, u1, w1)
        f = s + r * e
        C = (c, L, u, u1, e, f)
        return C

    def verify_ciphertext(self, cipher, g):
        # Check correctness of ciphertext
        (c, L, u, u1, e, f) = cipher
        w = (g ** f) / (u ** e)
        w1 = (g1 ** f) / (u1 ** e)
        H = hashH(c, L, u, w, u1, w1)
        assert e == H
        return True

    def verify_share(self, i, share, C, g):
        assert 0 <= i < self.l
        (u_i, e_i, f_i) = share
        (c, L, u, u1, e, f) = C
        h_i = self.VKs[i]
        u1_i = (u ** f_i) / (u_i ** e_i)
        h1_i = (g ** f_i) / (h_i ** e_i)
        H = hash4(u_i, u1_i, h1_i)
        assert e_i == H

        return True

    def combine_shares(self, C, shares):
        # sigs: a mapping from idx -> sig
        (c, L, u, u1, e, f) = C
        S = set(shares.keys())
        assert S.issubset(range(self.l))
        def mul(a, b): return a * b
        res = reduce(mul,
                     [share[0] ** self.lagrange(S, j)
                      for j, share in shares.items()])
        return xor(hashG(res), c)


class TDHPrivateKey(TDHPublicKey):
    def __init__(self, l, k, VK, VKs, SK, i):
        super(TDHPrivateKey, self).__init__(l, k, VK, VKs)
        assert 0 <= i < self.l
        self.i = i
        self.SK = SK
        self.g = g

    def decrypt_share(self, C, g):
        (c, L, u, u1, e, f) = C
        u_i = u ** self.SK
        si = group.random()
        u1_i = u ** si
        h1_i = g ** si
        e_i = hash4(u_i, u1_i, h1_i)
        f_i = si + self.SK * e_i
        S = (u_i, e_i, f_i)
        return S


def dealer(players=10, k=5):
    # Random polynomial coefficients
    secret = group.random()
    a = [secret]
    for i in range(1, k):
        a.append(group.random())
    assert len(a) == k

    # Polynomial evaluation
    def f(x):
        y = ZERO
        xx = ONE
        for coeff in a:
            y += coeff * xx
            xx *= x
        return y

    # Shares of master secret key
    SKs = [f(i) for i in range(1, players + 1)]
    assert f(0) == secret

    # Verification keys
    VK = g ** secret  # equal to public key h=h_0 = g^F(0)
    VKs = [g ** xx for xx in SKs]  # (h_1...h_n) where h_i = g^F(x_i)

    public_key = TDHPublicKey(players, k, VK, VKs)
    private_keys = [TDHPrivateKey(players, k, VK, VKs, SK, i)
                    for i, SK in enumerate(SKs)]

    # Check reconstruction of 0
    S = set(range(0, k))
    lhs = f(0)
    rhs = sum(public_key.lagrange(S, j) * f(j + 1) for j in S)
    assert lhs == rhs

    return public_key, private_keys, g


'''
def test():



    # g = deserialize(strtobytes(gg))
    # PK, SKs = TDHPublicKey(l, k, deserialize(strtobytes(sVK)), [deserialize(strtobytes(sVKp)) for sVKp in sVKs]), \
    #       [TDHPrivateKey(l, k, deserialize(strtobytes(sVK)), [deserialize(strtobytes(sVKp)) for sVKp in sVKs], \
    #                       deserialize(strtobytes(SKp[1])), SKp[0]) for SKp in SKs]
'''


BS = 16
def pad(s): return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad(s): return s[:-ord(s[len(s) - 1:])]


def encrypt(key, raw):
    assert len(key) == 32
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(raw))


def decrypt(key, enc):
    enc = (enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


def main():
    test()


if __name__ == '__main__':
    main()
