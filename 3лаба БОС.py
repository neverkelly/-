import hashlib


class LamportServer:
    def __init__(self, sync_window=5):
        self.users = {}
        self.sync_window = sync_window

    def register(self, username, last_hash, counter):
        self.users[username] = {
            "hash": last_hash,
            "counter": counter
        }

    def authenticate(self, username, otp):
        if username not in self.users:
            return False, "Пользователь не найден"

        user = self.users[username]
        stored_hash = user["hash"]

        current = otp

        for shift in range(self.sync_window + 1):

            if hashlib.sha256(current.encode()).hexdigest() == stored_hash:
                user["hash"] = current
                user["counter"] -= (shift + 1)

                return True, (
                    f"Успешная аутентификация "
                    f"(рассинхронизация: {shift})"
                )

            current = hashlib.sha256(current.encode()).hexdigest()

        return False, "Неверный пароль"


class LamportClient:
    def __init__(self, secret, n):
        self.secret = secret
        self.counter = n

    def hash_n_times(self, value, n):
        result = value

        for _ in range(n):
            result = hashlib.sha256(result.encode()).hexdigest()

        return result

    def get_registration_hash(self):
        return self.hash_n_times(self.secret, self.counter)

    def generate_otp(self):
        otp = self.hash_n_times(
            self.secret,
            self.counter - 1
        )

        self.counter -= 1

        return otp


N = 10
SECRET = "my_secret_password"

server = LamportServer(sync_window=3)
client = LamportClient(SECRET, N)

registration_hash = client.get_registration_hash()

server.register(
    "student",
    registration_hash,
    N
)

print("Регистрация выполнена")

for i in range(3):
    otp = client.generate_otp()
    result, msg = server.authenticate("student", otp)
    print(msg)

print("\nПроверка рассинхронизации")

client.generate_otp()
client.generate_otp()

otp = client.generate_otp()

result, msg = server.authenticate(
    "student",
    otp
)

print(msg)