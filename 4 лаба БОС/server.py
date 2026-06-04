import socket
import pickle
import struct
import secrets

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


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Сервер запущен")
print("Ожидание клиента...")

conn, addr = server.accept()

print("Подключен:", addr)

reg = recv_obj(conn)

n = reg["n"]
v = reg["v"]

print("Получен открытый ключ клиента")
print()

success = True

for rnd in range(ROUNDS):

    print(f"Раунд {rnd + 1}")

    data = recv_obj(conn)

    if data is None:
        success = False
        break

    x = data["x"]

    e = secrets.randbelow(2)

    send_obj(conn, {"e": e})

    data = recv_obj(conn)

    if data is None:
        success = False
        break

    y = data["y"]

    left = pow(y, 2, n)
    right = (x * pow(v, e, n)) % n

    print("e =", e)
    print("left =", left)
    print("right =", right)

    if left == right:
        print("Проверка пройдена\n")
    else:
        print("Проверка НЕ пройдена\n")
        success = False
        break

print("=" * 40)

if success:
    print("АУТЕНТИФИКАЦИЯ УСПЕШНА")
else:
    print("АУТЕНТИФИКАЦИЯ ПРОВАЛЕНА")

conn.close()
server.close()