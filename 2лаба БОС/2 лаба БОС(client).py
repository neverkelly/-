import socket
import hashlib
import os

#ПАРАМЕТРЫ
N = int(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E8607261877519"
    "55FFB6B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16
)
g = 2

def H(*args):
    a = ":".join(str(x) for x in args)
    return int(hashlib.sha256(a.encode()).hexdigest(), 16)

#ВВОД
username = "user"
password = "1234"

#СОКЕТ
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 5000))

#отправляем A
a = int.from_bytes(os.urandom(32), "big")
A = pow(g, a, N)

client.send(f"{username},{A}".encode())

#получаем salt и B
data = client.recv(4096).decode().split(",")
salt = bytes.fromhex(data[0])
B = int(data[1])

#вычисляем ключ
x = int(hashlib.sha256(salt + password.encode()).hexdigest(), 16)
u = H(A, B)

S = pow(B, a + u * x, N)
K = hashlib.sha256(str(S).encode()).digest()

#отправляем подтверждение
client_M = hashlib.sha256(K).digest()
client.send(client_M)

#РЕЗУЛЬТАТ
result = client.recv(4096).decode()
print("Результат:", result)

client.close()