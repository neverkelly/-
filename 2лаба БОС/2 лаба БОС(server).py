import socket
import hashlib
import os

#ПАРАМЕТРЫ SRP
N = int(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E8607261877519"
    "55FFB6B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16
)
g = 2

#ХЕШ ФУНКЦИЯ
def H(*args):
    a = ":".join(str(x) for x in args)
    return int(hashlib.sha256(a.encode()).hexdigest(), 16)

#РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ
def register_user(username, password):
    salt = os.urandom(32)  # salt = 32 байта (размер SHA-256)
    x = int(hashlib.sha256(salt + password.encode()).hexdigest(), 16)
    v = pow(g, x, N)
    return salt, v

#БАЗА (в памяти)
USER_DB = {}
username = "user"
password = "1234"

salt, v = register_user(username, password)
USER_DB[username] = (salt, v)

#СЕРВЕР
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 5000))
server.listen(1)

print("Сервер запущен...")

conn, addr = server.accept()
print("Подключение:", addr)

#получаем A
data = conn.recv(4096).decode().split(",")
I = data[0]  # логин
A = int(data[1])

salt, v = USER_DB[I]

#генерируем B
b = int.from_bytes(os.urandom(32), "big")
B = pow(g, b, N)

#отправляем salt и B
conn.send(f"{salt.hex()},{B}".encode())

#вычисляем общий ключ
u = H(A, B)
S = pow(A * pow(v, u, N), b, N)
K = hashlib.sha256(str(S).encode()).digest()

#проверка клиента
client_M = conn.recv(4096)

server_M = hashlib.sha256(K).digest()

if client_M == server_M:
    conn.send(b"OK")
    print("Аутентификация успешна")
else:
    conn.send(b"FAIL")
    print("Ошибка аутентификации")

conn.close()
server.close()