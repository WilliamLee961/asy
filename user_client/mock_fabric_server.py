from flask import Flask, request, jsonify
import json
import socket
import threading
from write_send import _Threshold
import struct
from write_send import tx_generator
from io import BytesIO
from write_send import tyke_str

app = Flask(__name__)


n=1  # 10
b = [None] * (n + 10)

for i in range(n):
    b[i] = tx_generator(20)

tyke, chm, ccACL = _Threshold(0,2,m=b[0].encode())
# tyke2, chm2, ccACL2 = _Threshold(0,2,m=b[2].encode())
value = {"Encryption method": tyke_str(tyke), "key": chm, "ACL": ccACL}
# value2 = {"Encryption method": tyke_str(tyke2), "key": chm2, "ACL": ccACL2}
# value 1, ...,9 
# mock_database = {"1"}

# 模拟数据库（或者说模拟的 Fabric 数据）
# mock_database = {
#     f"{i}": value
#     for i in range(10)
#     # "1": {"Encryption method": "Broadcast encryption", "ACL": "s1Y4Pai95IkN/hfU559MMY9ZlI3gyl60be+5QIYfsVRN2b6ZWU6OgEcHDu9wk1eFn9vvMCYO89joRI/RXz1Qn6fc98/BF2ctjZF0jZw4HRktScJjHDKLL9a+NGPTX0RwMjg/kWH4cu7njTLa8qH4aBe/NIPS2UaxcJhmJ4ntT5nSVWRn8eCkEYiDqERodYjX+130pgL1zcwjMgyp6jNnxhe4BGwhyDrzn0fKzvnFwlet81MVTem6erZzWKyPyodlgCq2FsxsDDgee4j8cpWY+NxUCPVZSl+TPZINsJeTo2+dj62mYC8MMLwhnO6KMs5SHGF1ha6JGE83uyB6OwmSEQ==", "key": "encrypted_key_1"},
#     # "2": {"Encryption method": "Attribute encryption", "ACL": "TJpoZ+eWq/wNG4M87m0sV5T5CfLuOgItJ8b6745uoRkY8bPfOMLpj8AQ+p9PFeJt9ziyMXzoingFKHZk5PGWUI34JhQ/YOyVrmaCYVWG2BlNzhHYJR/ff3uDUVh4J8Zsl3lcyz4PFj4j4gm9j2TcjXKSDrh2aFmz7Lo7oW9x1vqSwBIlK3mK9Q7Qscv6dDRXA0wjj5tpZthk14yQHEK6tWT5oRJrvThz8eLB/qIeoy4CSCGAp8k0GNvxYdyNELWb7thFP3DKdOlcGfI82tFNxjCkoOlIqhRRsNRZVMrUbGB2ZdP/zsPmvMl75xRPatqM++w7sh3qwfE5Rj4svS0f0g==", "key": "encrypted_key_2"},
#     # "3": {"Encryption method": "Threshold encryption", "ACL": "KEegij/vNhNN5izn5L9Ol84yNGrgmo7Wq9U4Hjr0wq3tg0ppKDRy2ZInahHMwSP3jKhLl42opjVUEtkwKzLdd3gVURG1RHJoh+n75o9yfLRu/OrZ/tlYiER/stfgWvx4PfuAYmpp6hUrGRVfI5L98STUholHOCC3WtSmkmKVLduez5AoKU0bFYOSz8gt2ImNVb1UOhzkrhlH7Niv5RBuHD2ysNkRMy7PwpyJ01wbMNE83xJ8nbdRzZcwB9uMkLwqLlrcfZWNLJU6AOF40gZaxyIu33A2KRJDxhZh4wTkmgJH1dCsh1bkdkAt28856dxwAJ4VHD2xPIC7i/S+Vd3cZg==", "key": "encrypted_key_3"},
#     # "4": {"Encryption method": "Broadcast encryption", "ACL": "nNo6oP9lQWL9tZTu6vRp57qb6ZUgEjLuG3Ymf+WVCUIzQeMlwEAUOrxQay52ZufohGxFOKHRKsT2wSZSegs1w6qDBIUbe6AyALEJmjU/Woj6220Kp/Z8N0AC50zG6Tspiex1mOoPQ6PhGTetPHIAgWreC/PJOcLWS+1Pm7CBIhVxQ2j7E5sZJ8SThw0uEhNOVNEVh2emSs3W0pLtJf8he8gnv/asspp+Ipeb2EtzgiCzu1IyzcdImnCMx/qd8dhwjeyfmETkfKeKczDyWz3bdWMftiixbTKH7jc3BF5DLweqP1GXPp5yp9GzVkMwdUYF+KtvSRCQiIY0N0B5E4+vvA==", "key": "encrypted_key_4"},
# }
mock_database = {
    "0": value,
    "1": value,
    "2": value,
    "3": value,
    "4": value,
    "5": value,
    "6": value,
    "7": value,
    "8": value,
    "9": value
    # "1": {"Encryption method": "Broadcast encryption", "ACL": "s1Y4Pai95IkN/hfU559MMY9ZlI3gyl60be+5QIYfsVRN2b6ZWU6OgEcHDu9wk1eFn9vvMCYO89joRI/RXz1Qn6fc98/BF2ctjZF0jZw4HRktScJjHDKLL9a+NGPTX0RwMjg/kWH4cu7njTLa8qH4aBe/NIPS2UaxcJhmJ4ntT5nSVWRn8eCkEYiDqERodYjX+130pgL1zcwjMgyp6jNnxhe4BGwhyDrzn0fKzvnFwlet81MVTem6erZzWKyPyodlgCq2FsxsDDgee4j8cpWY+NxUCPVZSl+TPZINsJeTo2+dj62mYC8MMLwhnO6KMs5SHGF1ha6JGE83uyB6OwmSEQ==", "key": "encrypted_key_1"},
    # "2": {"Encryption method": "Attribute encryption", "ACL": "TJpoZ+eWq/wNG4M87m0sV5T5CfLuOgItJ8b6745uoRkY8bPfOMLpj8AQ+p9PFeJt9ziyMXzoingFKHZk5PGWUI34JhQ/YOyVrmaCYVWG2BlNzhHYJR/ff3uDUVh4J8Zsl3lcyz4PFj4j4gm9j2TcjXKSDrh2aFmz7Lo7oW9x1vqSwBIlK3mK9Q7Qscv6dDRXA0wjj5tpZthk14yQHEK6tWT5oRJrvThz8eLB/qIeoy4CSCGAp8k0GNvxYdyNELWb7thFP3DKdOlcGfI82tFNxjCkoOlIqhRRsNRZVMrUbGB2ZdP/zsPmvMl75xRPatqM++w7sh3qwfE5Rj4svS0f0g==", "key": "encrypted_key_2"},
    # "3": {"Encryption method": "Threshold encryption", "ACL": "KEegij/vNhNN5izn5L9Ol84yNGrgmo7Wq9U4Hjr0wq3tg0ppKDRy2ZInahHMwSP3jKhLl42opjVUEtkwKzLdd3gVURG1RHJoh+n75o9yfLRu/OrZ/tlYiER/stfgWvx4PfuAYmpp6hUrGRVfI5L98STUholHOCC3WtSmkmKVLduez5AoKU0bFYOSz8gt2ImNVb1UOhzkrhlH7Niv5RBuHD2ysNkRMy7PwpyJ01wbMNE83xJ8nbdRzZcwB9uMkLwqLlrcfZWNLJU6AOF40gZaxyIu33A2KRJDxhZh4wTkmgJH1dCsh1bkdkAt28856dxwAJ4VHD2xPIC7i/S+Vd3cZg==", "key": "encrypted_key_3"},
    # "4": {"Encryption method": "Broadcast encryption", "ACL": "nNo6oP9lQWL9tZTu6vRp57qb6ZUgEjLuG3Ymf+WVCUIzQeMlwEAUOrxQay52ZufohGxFOKHRKsT2wSZSegs1w6qDBIUbe6AyALEJmjU/Woj6220Kp/Z8N0AC50zG6Tspiex1mOoPQ6PhGTetPHIAgWreC/PJOcLWS+1Pm7CBIhVxQ2j7E5sZJ8SThw0uEhNOVNEVh2emSs3W0pLtJf8he8gnv/asspp+Ipeb2EtzgiCzu1IyzcdImnCMx/qd8dhwjeyfmETkfKeKczDyWz3bdWMftiixbTKH7jc3BF5DLweqP1GXPp5yp9GzVkMwdUYF+KtvSRCQiIY0N0B5E4+vvA==", "key": "encrypted_key_4"},
}
# print(mock_database)

# 监听来自客户端的连接
def handle_client_connection(client_socket):
    try:
        # 接收客户端发送的数据
        data = client_socket.recv(1024)
        if data:
            # 解析接收到的数据
            print("Received encrypted data:", data)
            # 这里你可以对数据进行处理，例如存储到 mock_database 中，或者进行解密
            # 这部分根据你具体的需求来处理
            # 例如我们可以假设传来的数据包含一个 "key" 和 "value" 对，假设是 json 格式
            try:
                decrypted_data = json.loads(data.decode('utf-8'))  # 假设数据是 JSON 格式
                key = decrypted_data.get('key')
                value = decrypted_data.get('value')
                if key and value:
                    mock_database[key] = value
                    response = {"status": "success", "message": "Data stored successfully"}
                else:
                    response = {"status": "error", "message": "Invalid data format"}
            except Exception as e:
                response = {"status": "error", "message": f"Failed to process data: {str(e)}"}
            # 将响应返回给客户端
            client_socket.sendall(json.dumps(response).encode('utf-8'))
    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        # 关闭连接
        client_socket.close()

# 启动服务器，监听指定端口
def start_server(host='0.0.0.0', port=8521):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        # 使用线程处理客户端连接，防止阻塞
        client_handler = threading.Thread(target=handle_client_connection, args=(client_socket,))
        client_handler.start()

@app.route('/fabric/setData', methods=['POST'])
def set_data():
    try:
        # 从请求中获取数据
        fields = request.form.to_dict()
        # print(fields)
        key = fields.get("key")
        value = fields.get("value")
        # print(1)
        # 如果没有 key 或者 value 则返回错误
        if not key or not value:
            return jsonify({"error": "Missing 'key' or 'value' parameter"}), 400
        # print(2)
        # 上链：将元信息数据存储到模拟数据库
        mock_database[key] = value
        # print(3)
        # 返回成功响应
        return jsonify({"code": 200, "message": "Data successfully added to the chain"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/fabric/getData', methods=['GET'])
def get_data():
    key = request.args.get('key')
    
    if not key:
        return jsonify({"error": "Missing 'key' parameter"}), 400

    # 查找 key
    data = mock_database.get(key)
    if not data:
        return jsonify({"error": f"No data found for key {key}"}), 404

    # 返回模拟数据
    response = {
        "code": 200,
        "value": json.dumps(data)  # 这里返回的数据格式要与 query_chain 中的解析一致
    }
    return jsonify(response), 200

if __name__ == '__main__':
    # 启动服务器线程
    server_thread = threading.Thread(target=start_server, args=('127.0.0.1', 8522))
    server_thread.daemon = True  # 设置为守护线程，使主程序退出时自动关闭服务器
    server_thread.start()

    # 启动 Flask Web 服务
    app.run(host='0.0.0.0', port=8521)