import socket
import random
import hashlib
import base64

from cryptography.fernet import Fernet


HOST = '127.0.0.1'
PORT = 5000

# Простое большое простое число и генератор
p = 23
g = 5

# Секрет сервера
private_key = random.randint(1, p - 2)

# Открытый ключ сервера
public_key = pow(g, private_key, p)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Сервер запущен...")
conn, addr = server.accept()
print(f"Подключен клиент: {addr}")

# Отправляем параметры DH
conn.send(f"{p},{g},{public_key}".encode())

# Получаем открытый ключ клиента
client_public_key = int(conn.recv(1024).decode())

# Общий секрет
shared_secret = pow(client_public_key, private_key, p)

print("Общий секрет:", shared_secret)

# Генерация ключа Fernet
key = hashlib.sha256(str(shared_secret).encode()).digest()
fernet_key = base64.urlsafe_b64encode(key)

cipher = Fernet(fernet_key)

while True:
    encrypted_message = conn.recv(4096)

    if not encrypted_message:
        break

    decrypted = cipher.decrypt(encrypted_message).decode()

    if decrypted.lower() == "exit":
        print("Клиент завершил соединение")
        break

    print("Получено:", decrypted)

conn.close()
server.close()