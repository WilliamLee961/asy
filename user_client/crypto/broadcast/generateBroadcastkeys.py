import sys
from crypto.broadcast.fullbinarytree import findparents, deleteleaves, combinecorrectleaves, outputall, generatesecretinformation, generateciphertext, locatesameelement
from crypto.broadcast.AESCBC import AESCipher, generateAESCBCkey, generateAESCBCIV
from crypto.broadcast.Streamcipher import xor_crypt_string, generateStreamkey
import pickle

def Generate_broadcast_key(num_receivers):
    num_totalnodes = 2 * num_receivers - 1
    generateAESCBCkey(num_totalnodes)
    generateAESCBCIV()
    generatesecretinformation(num_receivers, num_totalnodes)
    generateStreamkey()

def Broadcast_encryption(num_leaf, nodes_deleted, key_streamcipher, m):
    mm = xor_crypt_string(m, key_streamcipher, encode=True)
    
    num_nodes = 2*num_leaf - 1
    flag = [True for i in range(num_nodes)]
    label = []
    flag = deleteleaves(flag,nodes_deleted)

    label = combinecorrectleaves(flag, label, num_leaf, num_nodes)
    
    list_content = generateciphertext(label, mm, 7)
    return list_content

def Broadcast_decryption(secret_information_list, IV, list_content):

    location_A, location_B = locatesameelement(list_content,secret_information_list)

    session_key = secret_information_list[location_B]
    stream_key = AESCipher(session_key).decrypt(list_content[location_A], IV)

    plaintext = xor_crypt_string(list_content[len(list_content) - 1], stream_key, decode = True)
    return plaintext


'''
Generate_broadcast_key(4)
nodes_deleted = [4]
list_content = broadcast_encryption(4, nodes_deleted, "123456")
print("list_content---",list_content)
broadcast_decryption(3, list_content)
'''
'''
if __name__ == "__main__":

    #num_receivers = readreceivernum()
    num_receivers = 4
    num_totalnodes = 2 * num_receivers - 1
    #first_receiver_num = num_totalnodes - num_receivers
    #revoked_client = readrevoked_client()[1:-1].split(",")
    #print "==========the receivers", revoked_client, "are revoked========"

    #Generate secret information for every receivers;
    #Step 1: for every nodes in full binary trees generate the AES session keys and store in ./config/AESsessionkeys file
    #generate AESCBC IV
    session_keysAESCBC = generateAESCBCkey(num_totalnodes)
    print("---------Every nodes has their session keys:-----------", session_keysAESCBC)
    generateAESCBCIV()
    #Step 2: for every receivers find their fathers and output
    #Step 3: for every non-revoked receivers and revoked receivers, generate the secret information and store in ./config/broadenckeys
    generatesecretinformation(num_receivers, num_totalnodes)

    #num_ofreceivers = readnum_receivers()

    #Ensure the specified receiver

    real_seq_client = 3

    #print real_seq_client

    generateStreamkey()

    #Get the secret information from the files ./config/broadenckeys/

    filename = "./config/broadenckeys/%d.keys"%real_seq_client 

    secret_information_list = []

    secret_information_list = pickle.loads( open(filename, 'rb').read()) 
   
    open(filename, 'r').close()
    print("secret_information_list ---",secret_information_list )
    #print secret_information_list

    #Get the location of secret information and ciphertext
    
    
    m = "王文卓吃汉堡"
    filename = "./config/streamcipher.keys"
    key_streamcipher = open(filename, 'rb').read()
    print("key_streamcipher---",key_streamcipher)
    
    mm = xor_crypt_string(m.encode("utf-8"), key_streamcipher, encode=True)
    label = [2, 3]
    list_content = generateciphertext(label, mm, 7)
    print("list_content---",list_content)
    location_A, location_B = locatesameelement(list_content,secret_information_list)

    #generate the streamcipher key

    #print "This is location_A", location_A

    #print "This is location_B", location_B

    filename = "./config/AESCBCIV.keys"

    IV = pickle.loads ( open(filename, 'rb').read() ) 

    open(filename, 'r').close() 

    session_key = secret_information_list[location_B]

    #print "This is session key", session_key

    stream_key = AESCipher(session_key).decrypt(list_content[location_A], IV)

    #print "This is stream key", stream_key

    #decrypt the ciphertext with F_k

    plaintext = xor_crypt_string(list_content[len(list_content) - 1], stream_key, decode = True)
    print("plaintext---",plaintext.decode("utf-8"))
'''
