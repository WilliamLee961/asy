from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def rsa_encipher(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')