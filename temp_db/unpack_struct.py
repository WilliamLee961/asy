import struct
from io import BytesIO

def db_unpack(b):
    buf = BytesIO(b)
    tyke_bytes = buf.read(4)
    tyke, = struct.unpack("<i", tyke_bytes)
    # print("tyke---",tyke)
    hm_len_bytes = buf.read(4)
    hm_len, = struct.unpack("<i", hm_len_bytes)
    hm = buf.read(hm_len)

    cm_len_bytes = buf.read(4)
    cm_len, = struct.unpack("<i", cm_len_bytes)
    cm = buf.read(cm_len)

    return tyke, hm, cm