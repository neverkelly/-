import socket
import random
import hashlib
import base64

from cryptography.fernet import Fernet


HOST = '127.0.0.1'
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Получаем параметры DH
data = client.recv(1024).decode()
p, g, server_public_key = map(int, data.split(','))

# Секрет клиента
private_key = random.randint(1, p - 2)

# Открытый ключ клиента
public_key = pow(g, private_key, p)

# Отправляем серверу
client.send(str(public_key).encode())

# Общий секрет
shared_secret = pow(server_public_key, private_key, p)

print("Общий секрет:", shared_secret)

# Генерация ключа Fernet
key = hashlib.sha256(str(shared_secret).encode()).digest()
fernet_key = base64.urlsafe_b64encode(key)

cipher = Fernet(fernet_key)

while True:
    message = input("Введите сообщение: ")

    encrypted = cipher.encrypt(message.encode())

    client.send(encrypted)

    if message.lower() == "exit":
        break

client.close()