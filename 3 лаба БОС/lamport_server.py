"""
Лабораторная работа №3 — Схема Лэмпорта (OTP)
==============================================
Серверная часть: хранит пользователей, проверяет OTP,
обрабатывает рассинхронизацию счётчиков.
"""

import hashlib
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, asdict
from typing import Optional

# ─────────────────────────────────────────────────────────────
#  Параметры схемы
# ─────────────────────────────────────────────────────────────
HASH_ALGO        = "sha256"
CHAIN_LENGTH     = 1000          # максимальное число шагов цепочки
RESYNC_WINDOW    = 20            # окно поиска при рассинхронизации
MAX_RESYNC_TRIES = 3             # попыток ресинхронизации до блокировки
LOCK_TIMEOUT     = 60            # секунд блокировки после превышения попыток


# ─────────────────────────────────────────────────────────────
#  Хэш-функция
# ─────────────────────────────────────────────────────────────
def H(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def hash_chain(seed: bytes, n: int) -> bytes:
    """Вычисляет H^n(seed) — применяет хэш n раз."""
    value = seed
    for _ in range(n):
        value = H(value)
    return value


# ─────────────────────────────────────────────────────────────
#  Хранилище пользователей (in-memory; можно заменить на БД)
# ─────────────────────────────────────────────────────────────
@dataclass
class UserRecord:
    username:       str
    expected_otp:   bytes    # H^counter(seed) — то, что сервер ожидает следующим
    counter:        int      # сколько хэшей осталось в цепочке (убывает)
    resync_tries:   int = 0
    locked_until:   float = 0.0
    last_login:     Optional[float] = None


class UserDatabase:
    def __init__(self):
        self._users: dict[str, UserRecord] = {}
        self._lock = threading.Lock()

    # ── регистрация ──────────────────────────────────────────
    def register(self, username: str, seed: bytes,
                 chain_length: int = CHAIN_LENGTH) -> bytes:
        """
        Регистрирует пользователя.
        Сервер хранит H^chain_length(seed).
        Возвращает H^chain_length(seed) (для проверки клиентом).
        """
        with self._lock:
            if username in self._users:
                raise ValueError(f"Пользователь '{username}' уже существует")
            top = hash_chain(seed, chain_length)
            self._users[username] = UserRecord(
                username=username,
                expected_otp=top,
                counter=chain_length,
            )
            return top

    # ── получение записи ─────────────────────────────────────
    def get(self, username: str) -> Optional[UserRecord]:
        return self._users.get(username)

    def update(self, record: UserRecord):
        with self._lock:
            self._users[record.username] = record


# ─────────────────────────────────────────────────────────────
#  Логика аутентификации
# ─────────────────────────────────────────────────────────────
class LamportAuthServer:
    """Реализует проверку OTP и механизм ресинхронизации."""

    def __init__(self, db: UserDatabase):
        self.db = db

    # ── основная проверка ─────────────────────────────────────
    def authenticate(self, username: str, otp: bytes) -> dict:
        rec = self.db.get(username)
        if rec is None:
            return self._fail("Пользователь не найден")

        now = time.time()
        if rec.locked_until > now:
            secs = int(rec.locked_until - now)
            return self._fail(f"Аккаунт заблокирован. Осталось {secs} с.")

        if rec.counter <= 0:
            return self._fail("Цепочка паролей исчерпана. Требуется перерегистрация.")

        # ── нормальная проверка ──────────────────────────────
        #  Клиент прислал OTP_i = H^(counter-1)(seed).
        #  Сервер знает OTP_{i-1..top} = expected_otp = H^counter(seed).
        #  Значит: H(otp_client) == expected_otp  ⟹  OK
        if H(otp) == rec.expected_otp:
            rec.expected_otp = otp          # сдвигаем ожидаемое значение
            rec.counter     -= 1
            rec.resync_tries = 0
            rec.last_login   = now
            self.db.update(rec)
            return self._ok(f"Успешный вход. Осталось паролей: {rec.counter}")

        # ── рассинхронизация: ищем в окне ───────────────────
        return self._try_resync(rec, otp, now)

    # ── ресинхронизация ───────────────────────────────────────
    def _try_resync(self, rec: UserRecord, otp: bytes, now: float) -> dict:
        """
        Если счётчик клиента ушёл вперёд (клиент сгенерировал лишние OTP),
        ищем подходящее значение в окне RESYNC_WINDOW шагов.
        """
        candidate = otp
        for step in range(1, RESYNC_WINDOW + 1):
            candidate = H(candidate)            # поднимаемся по цепочке
            if candidate == rec.expected_otp:
                # нашли: клиент опередил сервер на step шагов
                rec.expected_otp = otp          # принимаем текущий OTP
                rec.counter     -= (step + 1)   # корректируем счётчик
                rec.resync_tries = 0
                rec.last_login   = now
                self.db.update(rec)
                return self._ok(
                    f"Ресинхронизация выполнена (сдвиг +{step}). "
                    f"Осталось паролей: {rec.counter}"
                )

        # OTP не найден в окне — считаем неверным
        rec.resync_tries += 1
        if rec.resync_tries >= MAX_RESYNC_TRIES:
            rec.locked_until = now + LOCK_TIMEOUT
            rec.resync_tries = 0
            self.db.update(rec)
            return self._fail(
                f"Аккаунт заблокирован на {LOCK_TIMEOUT} с. "
                f"Превышено число неудачных попыток."
            )

        self.db.update(rec)
        left = MAX_RESYNC_TRIES - rec.resync_tries
        return self._fail(
            f"Неверный OTP. "
            f"Осталось попыток до блокировки: {left}"
        )

    # ── вспомогательные ───────────────────────────────────────
    @staticmethod
    def _ok(msg: str) -> dict:
        return {"status": "ok", "message": msg}

    @staticmethod
    def _fail(msg: str) -> dict:
        return {"status": "error", "message": msg}


# ─────────────────────────────────────────────────────────────
#  TCP-сервер
# ─────────────────────────────────────────────────────────────
class TCPServer:
    """
    Простой многопоточный TCP-сервер.
    Протокол: каждое сообщение — JSON-строка, завершённая '\n'.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9000):
        self.host = host
        self.port = port
        self.db   = UserDatabase()
        self.auth = LamportAuthServer(self.db)

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(10)
        print(f"[SERVER] Сервер запущен на {self.host}:{self.port}")
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
            t.start()

    # ── обработчик одного клиента ─────────────────────────────
    def _handle(self, conn: socket.socket, addr):
        print(f"[SERVER] Подключение от {addr}")
        buf = ""
        try:
            while True:
                data = conn.recv(4096).decode()
                if not data:
                    break
                buf += data
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line.strip():
                        continue
                    response = self._dispatch(line)
                    conn.sendall((json.dumps(response) + "\n").encode())
        except Exception as e:
            print(f"[SERVER] Ошибка: {e}")
        finally:
            conn.close()
            print(f"[SERVER] Соединение с {addr} закрыто")

    # ── маршрутизация команд ──────────────────────────────────
    def _dispatch(self, raw: str) -> dict:
        try:
            msg = json.loads(raw)
            cmd = msg.get("cmd")

            if cmd == "register":
                seed  = bytes.fromhex(msg["seed"])
                chain = int(msg.get("chain_length", CHAIN_LENGTH))
                top   = self.db.register(msg["username"], seed, chain)
                print(f"[SERVER] Зарегистрирован: {msg['username']} (цепочка={chain})")
                return {"status": "ok", "top_hash": top.hex()}

            elif cmd == "auth":
                otp    = bytes.fromhex(msg["otp"])
                result = self.auth.authenticate(msg["username"], otp)
                status = "✓" if result["status"] == "ok" else "✗"
                print(f"[SERVER] Аутентификация {msg['username']}: "
                      f"{status} {result['message']}")
                return result

            elif cmd == "status":
                rec = self.db.get(msg["username"])
                if rec is None:
                    return {"status": "error", "message": "Не найден"}
                return {
                    "status":  "ok",
                    "counter": rec.counter,
                    "locked":  rec.locked_until > time.time(),
                }
            else:
                return {"status": "error", "message": f"Неизвестная команда: {cmd}"}

        except Exception as e:
            return {"status": "error", "message": str(e)}


# ─────────────────────────────────────────────────────────────
#  Точка входа
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    server = TCPServer()
    server.start()
