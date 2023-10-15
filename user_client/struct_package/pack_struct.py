import struct
from io import BytesIO
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
import json
def _pack(tyke, fields, key, m):
    buf = BytesIO()

    buf.write(struct.pack("<i", tyke))

    buf.write(struct.pack("<i", len(fields)))
    buf.write(fields)

    buf.write(struct.pack("<i", len(key)))
    buf.write(key)
    if tyke == 1:
        mm = broadcast_pack(m)
        buf.write(struct.pack("<i", len(mm)))
        buf.write(mm)
    elif tyke == 2:
        buf.write(struct.pack("<i", len(m)))
        buf.write(m)
    elif tyke == 3:
        mm = attribute_pack(m)
        buf.write(struct.pack("<i", len(mm)))
        buf.write(mm)
    elif tyke == 4:
        buf.write(struct.pack("<i", len(m)))
        buf.write(m)
    elif tyke == 5:
        buf.write(struct.pack("<i", len(m)))
        buf.write(m)
    elif tyke == 6:
        buf.write(struct.pack("<i", len(m)))
        buf.write(m)
    
    buf.seek(0)
    return buf.read()



def _pack_sgx(tyke, key, m):
    buf = BytesIO()

    buf.write(struct.pack("<i", tyke))

    buf.write(struct.pack("<i", len(key)))
    buf.write(key)
    
    buf.write(struct.pack("<i", len(m)))
    buf.write(m)
    
    buf.seek(0)
    return buf.read()

def broadcast_pack(list_content):
    buf = BytesIO()
    
    list_1 = list_content[0]
    list_1_len = len(list_1)
    
    buf.write(struct.pack("<i", list_1_len))
    for i in range(list_1_len):
        buf.write(struct.pack("<i" ,list_1[i]))
    for i in range(list_1_len):
        va = list_content[i+1]
        buf.write(struct.pack("<i", len(va)))
        buf.write(va)
    fx = list_content[len(list_content) - 1]
    buf.write(struct.pack("<i", len(fx)))
    buf.write(fx)
    
    buf.seek(0)
    return buf.read()

def element_to_bytes(element):
    group = PairingGroup('SS512')
    serialized_bytes = group.serialize(element)

    return serialized_bytes

def bytes_to_element(element_bytes):
    group = PairingGroup('SS512')
    element = group.deserialize(element_bytes)

    return element

def attribute_pack(m):
    ctxt = m[0]
    msg = m[1]
    
    buf = BytesIO()
    
    policy = ctxt['policy']
    policy_str = str(policy)
    policy_bytes = policy_str.encode()
    policy_bytes_len = len(policy_bytes)
    buf.write(struct.pack("<i", policy_bytes_len))
    buf.write( policy_bytes)
    
    C_0 = ctxt['C_0']
    C_0_len = len(C_0)
    buf.write(struct.pack("<i", C_0_len))
    for i in range(C_0_len):
        x = C_0[i]
        x_bytes = element_to_bytes(x)
        x_bytes_len = len(x_bytes)
        buf.write(struct.pack("<i", x_bytes_len))
        buf.write(x_bytes)
    
    C = ctxt['C']
    C_len = len(C)
    buf.write(struct.pack("<i", C_len))
    for x in C:
        x_bytes = x.encode()
        x_bytes_len = len(x_bytes)
        buf.write(struct.pack("<i", x_bytes_len))
        buf.write(x_bytes)
        #print("Cx---",x)
        a = C[x]
        a_len = len(a)
        buf.write(struct.pack("<i", a_len))
        for i in range(a_len):
            y = a[i]
            y_bytes = element_to_bytes(y)
            y_bytes_len = len(y_bytes)
            buf.write(struct.pack("<i", y_bytes_len))
            buf.write(y_bytes)
    
    Cp = ctxt['Cp']
    Cp_bytes = element_to_bytes(Cp)
    Cp_bytes_len = len(Cp_bytes)
    buf.write(struct.pack("<i", Cp_bytes_len))
    buf.write( Cp_bytes)
    
    msg_len = len(msg)
    buf.write(struct.pack("<i", msg_len))
    buf.write( msg)
    
    buf.seek(0)
    return buf.read()
    
    
    
    
    
    
    
    
    
    
    
    


