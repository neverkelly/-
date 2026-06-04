"""
Лабораторная работа №3 — Схема Лэмпорта (OTP)
==============================================
Клиентская часть: генерирует seed, строит цепочку,
выдаёт OTP в порядке убывания номеров.
"""

import hashlib
import json
import os
import socket
from dataclasses import dataclass
from typing import Optional


# ─────────────────────────────────────────────────────────────
#  Хэш-функция (должна совпадать с серверной)
# ─────────────────────────────────────────────────────────────
HASH_ALGO = "sha256"


def H(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def hash_chain(seed: bytes, n: int) -> bytes:
    value = seed
    for _ in range(n):
        value = H(value)
    return value


# ─────────────────────────────────────────────────────────────
#  Состояние клиента
# ─────────────────────────────────────────────────────────────
@dataclass
class ClientState:
    username:     str
    seed:         bytes
    chain_length: int
    counter:      int       # текущий индекс (убывает от chain_length до 0)

    def current_otp(self) -> Optional[bytes]:
        """OTP для текущего шага: H^(counter-1)(seed)."""
        if self.counter <= 0:
            return None
        return hash_chain(self.seed, self.counter - 1)

    def advance(self):
        """Сдвинуть счётчик после успешной аутентификации."""
        if self.counter > 0:
            self.counter -= 1

    def force_counter(self, new_counter: int):
        """Принудительно задать счётчик (ручная ресинхронизация)."""
        self.counter = new_counter


# ─────────────────────────────────────────────────────────────
#  TCP-соединение с сервером
# ─────────────────────────────────────────────────────────────
class ServerConnection:
    def __init__(self, host: str = "127.0.0.1", port: int = 9000):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._buf  = ""

    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.host, self.port))
        self._buf = ""

    def disconnect(self):
        if self._sock:
            self._sock.close()
            self._sock = None

    def send(self, msg: dict) -> dict:
        if self._sock is None:
            raise ConnectionError("Нет соединения с сервером")
        data = (json.dumps(msg) + "\n").encode()
        self._sock.sendall(data)
        return self._recv()

    def _recv(self) -> dict:
        while "\n" not in self._buf:
            chunk = self._sock.recv(4096).decode()
            if not chunk:
                raise ConnectionError("Сервер закрыл соединение")
            self._buf += chunk
        line, self._buf = self._buf.split("\n", 1)
        return json.loads(line)


# ─────────────────────────────────────────────────────────────
#  Клиент схемы Лэмпорта
# ─────────────────────────────────────────────────────────────
class LamportClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 9000):
        self.conn  = ServerConnection(host, port)
        self.state: Optional[ClientState] = None

    # ── подключение ───────────────────────────────────────────
    def connect(self):
        self.conn.connect()

    def disconnect(self):
        self.conn.disconnect()

    # ── регистрация ───────────────────────────────────────────
    def register(self, username: str,
                 chain_length: int = 1000,
                 seed: Optional[bytes] = None) -> dict:
        """
        1. Генерирует случайный seed (или использует переданный).
        2. Отправляет серверу seed + chain_length.
        3. Сохраняет состояние.
        """
        if seed is None:
            seed = os.urandom(32)

        resp = self.conn.send({
            "cmd":          "register",
            "username":     username,
            "seed":         seed.hex(),
            "chain_length": chain_length,
        })

        if resp["status"] == "ok":
            # Верифицируем: сервер должен был сохранить H^n(seed)
            expected_top = hash_chain(seed, chain_length)
            received_top = bytes.fromhex(resp["top_hash"])
            if expected_top != received_top:
                raise ValueError("Сервер вернул неверный top_hash!")

            self.state = ClientState(
                username=username,
                seed=seed,
                chain_length=chain_length,
                counter=chain_length,
            )

        return resp

    # ── аутентификация ────────────────────────────────────────
    def authenticate(self) -> dict:
        """Отправляет текущий OTP серверу."""
        if self.state is None:
            raise RuntimeError("Клиент не зарегистрирован")
        if self.state.counter <= 0:
            return {"status": "error", "message": "Цепочка исчерпана"}

        otp  = self.state.current_otp()
        resp = self.conn.send({
            "cmd":      "auth",
            "username": self.state.username,
            "otp":      otp.hex(),
        })

        if resp["status"] == "ok":
            self.state.advance()

        return resp

    # ── имитация рассинхронизации ─────────────────────────────
    def skip_passwords(self, n: int):
        """
        Симулирует рассинхронизацию: клиент 'теряет' n паролей,
        сдвигая свой счётчик вперёд без уведомления сервера.
        """
        if self.state is None:
            raise RuntimeError("Клиент не зарегистрирован")
        self.state.counter = max(0, self.state.counter - n)

    # ── ручная ресинхронизация счётчика клиента ───────────────
    def resync_counter(self, new_counter: int):
        """Принудительно задать счётчик (например, после получения
        актуального значения от сервера по доп. каналу)."""
        if self.state is None:
            raise RuntimeError("Клиент не зарегистрирован")
        self.state.force_counter(new_counter)

    # ── запрос статуса с сервера ──────────────────────────────
    def get_server_status(self) -> dict:
        if self.state is None:
            raise RuntimeError("Клиент не зарегистрирован")
        return self.conn.send({"cmd": "status", "username": self.state.username})

    # ── вспомогательные ───────────────────────────────────────
    @property
    def counter(self) -> int:
        return self.state.counter if self.state else 0

    @property
    def username(self) -> str:
        return self.state.username if self.state else ""
