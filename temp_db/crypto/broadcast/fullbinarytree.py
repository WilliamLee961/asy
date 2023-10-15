import pickle
from crypto.broadcast.AESCBC import AESCipher, generateAESCBCkey

def locatesameelement(list_content, secret_information_list):
    lable_1 = list_content[0]
    lable_2 = secret_information_list[0]

    location_A = 0
    location_B = 0
    for i in range(len(lable_1)):
        for j in range(len(lable_2)):
            if lable_1[i] == lable_2[j]:
                location_A = i
                location_B = j
    return location_A+1, location_B+1
    
def generateciphertext(label, F_k, num_totalnodes):
    ciphertext = []
    ciphertext.append(label)
    filename = "./config/AESsession%s.keys"%num_totalnodes
    session_keysAESCBC = []
    session_keysAESCBC =  pickle.loads( open(filename, 'rb').read())
    filename = "./config/streamcipher.keys"
    key_streamcipher = open(filename, 'rb').read()
    filename = "./config/AESCBCIV.keys"
    IV = pickle.loads ( open(filename, 'rb').read() )    
    for i in range(len(label)):
        value = AESCipher(session_keysAESCBC[label[i]]).encrypt(key_streamcipher.decode("ISO-8859-1"), IV)
        ciphertext.append(value)
    ciphertext.append(F_k)
    return ciphertext

def outputall(num_receivers, num_totalnodes):
    children_parents = {}
    for i in range(num_totalnodes - num_receivers, num_totalnodes):
        children_parents.setdefault(i, findparents(i))
    return children_parents

def generatesecretinformation(num_receivers, num_totalnodes):
    single_secret_information = []
    total_secret_information = outputall(num_receivers, num_totalnodes)

    filename = "./config/AESsession%s.keys"%num_totalnodes
    session_keysAESCBC = []
    session_keysAESCBC =  pickle.loads(open(filename, 'rb').read())

    for i in range(num_totalnodes - num_receivers, num_totalnodes):
        single_secret_information = []
        single_secret_information.append(total_secret_information.get(i))

        for j in single_secret_information[0]:
            single_secret_information.append(session_keysAESCBC[j])

        f = open("./config/broadenckeys/%d.keys"%i,"wb+")
        f.write(pickle.dumps(single_secret_information))
        f.close()

def findparents(index):
    parent=[]
    parent.append(index)
    while index > 0:
        parent.append( (index-1)// 2 )
        index = (index - 1) // 2
    return parent

#Step one: set the flag of leaf and its parents:
def deleteleaves(flag, nodes_deleted):
    for i in range(len(nodes_deleted)):
        flag[nodes_deleted[i]] = False
        root = (nodes_deleted[i] - 1)//2
        while root > 0 and flag[root]:
            flag[root] = False
            root = (root -1)//2
        flag[0] = False
    return flag


#Step two: commbine all the right leaves:
def combinecorrectleaves(flag, label, num_leaf, num_nodes):
    for i in range(num_nodes-num_leaf,num_nodes):
        if flag[i]:
            root = i
            while root > 0 and flag[(root-1)//2]:
                root = (root - 1)//2
            if root not in label:
                label.append(root)
            #keys[i] = keys[root]
            #if keys[root] not in label:
               # label.append(keys[root])
    return label


'''
#generatesecretinformation(4,7)
num_leaf = 4
#total of numbers
num_nodes = 2*num_leaf - 1
nodes = [i for i in range(num_nodes)]
flag = [True for i in range(num_nodes)]
keys = [i for i in range(num_nodes)]
nodes_deleted = [4]
label = []

flag = deleteleaves(flag,nodes_deleted)
print("flag---",flag)
label = combinecorrectleaves(flag, label, num_leaf, num_nodes)
print("label---",label)
'''
