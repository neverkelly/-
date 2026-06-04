import socket
import pickle
import struct
import secrets

from common import generate_keys

HOST = "127.0.0.1"
PORT = 5000

ROUNDS = 16


def send_obj(sock, obj):
    data = pickle.dumps(obj)

    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)


def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        packet = sock.recv(size - len(data))

        if not packet:
            return None

        data += packet

    return data


def recv_obj(sock):
    raw_size = recv_exact(sock, 4)

    if raw_size is None:
        return None

    size = struct.unpack("!I", raw_size)[0]

    data = recv_exact(sock, size)

    if data is None:
        return None

    return pickle.loads(data)


print("Генерация ключей...")

n, s, v = generate_keys()

print("n =", n)
print("s =", s)
print("v =", v)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

print("Подключение выполнено")

send_obj(client, {
    "n": n,
    "v": v
})

for rnd in range(ROUNDS):

    print(f"Раунд {rnd + 1}")

    r = secrets.randbelow(n - 1) + 1

    x = pow(r, 2, n)

    send_obj(client, {"x": x})

    challenge = recv_obj(client)

    e = challenge["e"]

    print("Получен e =", e)

    y = (r * pow(s, e, n)) % n

    send_obj(client, {"y": y})

    print("Отправлен y\n")

print("=" * 40)
print("Протокол завершён")

client.close()