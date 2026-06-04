"""
Лабораторная работа №3 — Схема Лэмпорта (OTP)
==============================================
demo.py — Демонстрация всех сценариев:
  1. Регистрация и нормальный вход
  2. Несколько последовательных входов
  3. Неверный OTP
  4. Рассинхронизация счётчика + автоматическое восстановление
  5. Многократные неверные попытки → блокировка
  6. Исчерпание цепочки
"""

import os
import sys
import threading
import time
import hashlib

# Добавляем текущую директорию в путь
sys.path.insert(0, os.path.dirname(__file__))

from lamport_server import TCPServer
from lamport_client import LamportClient


# ─────────────────────────────────────────────────────────────
#  Вывод с оформлением
# ─────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"

def hr(char="─", width=62, color=DIM):
    print(f"{color}{char * width}{RESET}")

def header(text: str, color=CYAN):
    hr("═", color=color)
    print(f"{color}{BOLD}  {text}{RESET}")
    hr("═", color=color)

def section(text: str):
    print(f"\n{BLUE}{BOLD}▶ {text}{RESET}")
    hr("─", color=DIM)

def ok(text: str):
    print(f"  {GREEN}✔ {text}{RESET}")

def err(text: str):
    print(f"  {RED}✘ {text}{RESET}")

def warn(text: str):
    print(f"  {YELLOW}⚠ {text}{RESET}")

def info(text: str):
    print(f"  {CYAN}ℹ {text}{RESET}")

def show_resp(resp: dict):
    msg = resp.get("message", resp.get("top_hash", str(resp)))
    if resp["status"] == "ok":
        ok(msg)
    else:
        err(msg)

def show_otp(client: LamportClient):
    otp = client.state.current_otp()
    if otp:
        short = otp.hex()[:16] + "…"
        info(f"OTP#{client.counter:>4}  {MAGENTA}{short}{RESET}  "
             f"(счётчик клиента: {client.counter})")


# ─────────────────────────────────────────────────────────────
#  Запуск сервера в отдельном потоке
# ─────────────────────────────────────────────────────────────
def start_server():
    srv = TCPServer(host="127.0.0.1", port=9001)
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    time.sleep(0.4)   # даём серверу подняться
    return srv


# ─────────────────────────────────────────────────────────────
#  Сценарии
# ─────────────────────────────────────────────────────────────
def scenario_normal_auth(host, port):
    """Сценарий 1: нормальная регистрация и последовательные входы."""
    header("Сценарий 1 — Нормальная аутентификация", CYAN)

    c = LamportClient(host, port)
    c.connect()

    section("Регистрация пользователя alice (цепочка = 10)")
    resp = c.register("alice", chain_length=10)
    show_resp(resp)
    info(f"Верхний хэш цепочки: {resp['top_hash'][:32]}…")

    section("Три последовательных входа")
    for i in range(1, 4):
        show_otp(c)
        resp = c.authenticate()
        print(f"  Вход #{i}: ", end="")
        show_resp(resp)

    c.disconnect()
    print()


def scenario_wrong_otp(host, port):
    """Сценарий 2: неверный OTP."""
    header("Сценарий 2 — Неверный OTP", YELLOW)

    c = LamportClient(host, port)
    c.connect()

    section("Регистрация пользователя bob")
    c.register("bob", chain_length=10)
    ok("Пользователь bob зарегистрирован")

    section("Подмена OTP случайными байтами")
    bad_otp = os.urandom(32).hex()
    from lamport_client import ServerConnection
    # отправим вручную
    import json, socket
    s = socket.socket()
    s.connect((host, port))
    s.sendall((json.dumps({"cmd": "auth", "username": "bob", "otp": bad_otp}) + "\n").encode())
    raw = b""
    while b"\n" not in raw:
        raw += s.recv(4096)
    resp = json.loads(raw.split(b"\n")[0])
    s.close()
    show_resp(resp)

    section("Нормальный вход после неверного OTP")
    show_otp(c)
    resp = c.authenticate()
    show_resp(resp)

    c.disconnect()
    print()


def scenario_resync(host, port):
    """Сценарий 3: рассинхронизация счётчиков."""
    header("Сценарий 3 — Рассинхронизация счётчиков", MAGENTA)

    c = LamportClient(host, port)
    c.connect()

    section("Регистрация пользователя charlie (цепочка = 50)")
    c.register("charlie", chain_length=50)
    ok("charlie зарегистрирован, счётчик = 50")

    section("Нормальный вход (×2)")
    for i in range(2):
        resp = c.authenticate()
        ok(f"Вход #{i+1}: {resp['message']}")

    section("Имитация потери 5 паролей (счётчик клиента уходит вперёд)")
    warn(f"Счётчик клиента до сдвига:  {c.counter}")
    c.skip_passwords(5)
    warn(f"Счётчик клиента после сдвига: {c.counter}  (сервер пока не знает)")

    section("Попытка войти с 'будущим' OTP → ресинхронизация")
    show_otp(c)
    resp = c.authenticate()
    if resp["status"] == "ok":
        ok(f"Ресинхронизация прошла: {resp['message']}")
    else:
        err(resp["message"])

    section("Два нормальных входа после ресинхронизации")
    for i in range(2):
        resp = c.authenticate()
        ok(f"Вход: {resp['message']}")

    c.disconnect()
    print()


def scenario_lockout(host, port):
    """Сценарий 4: блокировка после превышения попыток."""
    header("Сценарий 4 — Блокировка аккаунта", RED)

    import json, socket as sk

    def raw_auth(username, otp_hex):
        s = sk.socket()
        s.connect((host, port))
        s.sendall((json.dumps({"cmd": "auth", "username": username, "otp": otp_hex}) + "\n").encode())
        raw = b""
        while b"\n" not in raw:
            raw += s.recv(4096)
        s.close()
        return json.loads(raw.split(b"\n")[0])

    c = LamportClient(host, port)
    c.connect()

    section("Регистрация пользователя dave")
    c.register("dave", chain_length=20)
    ok("dave зарегистрирован")

    section(f"Отправляем {4} случайных OTP вне окна ресинхронизации")
    for i in range(1, 5):
        bad = os.urandom(32).hex()
        resp = raw_auth("dave", bad)
        print(f"  Попытка #{i}: ", end="")
        show_resp(resp)

    section("Попытка войти с правильным OTP в состоянии блокировки")
    resp = c.authenticate()
    show_resp(resp)

    c.disconnect()
    print()


def scenario_chain_exhausted(host, port):
    """Сценарий 5: исчерпание цепочки."""
    header("Сценарий 5 — Исчерпание цепочки паролей", YELLOW)

    c = LamportClient(host, port)
    c.connect()

    section("Регистрация пользователя eve (цепочка = 3)")
    c.register("eve", chain_length=3)
    ok("eve зарегистрирована, цепочка = 3")

    section("Используем все 3 пароля")
    for i in range(1, 4):
        show_otp(c)
        resp = c.authenticate()
        ok(f"Вход #{i}: {resp['message']}")

    section("Попытка 4-го входа (цепочка исчерпана)")
    resp = c.authenticate()
    show_resp(resp)

    c.disconnect()
    print()


def show_theory():
    """Краткое теоретическое описание схемы."""
    header("Схема одноразовых паролей Лэмпорта (Lamport OTP)", BLUE)

    lines = [
        ("Принцип", "Цепочка хэшей H^n(seed), H^(n-1)(seed), …, H^1(seed)"),
        ("Регистрация", "Сервер получает seed → хранит H^n(seed) = top"),
        ("Вход #1",     "Клиент отправляет OTP₁ = H^(n-1)(seed); сервер проверяет H(OTP₁)==top"),
        ("Вход #k",     "Клиент отправляет OTPₖ = H^(n-k)(seed); сервер сдвигает ожидание вниз"),
        ("Безопасность","Зная OTPₖ, вычислить OTPₖ₋₁ = H⁻¹(OTPₖ) вычислительно невозможно"),
        ("Рессинх.",    "Сервер ищет подходящее значение в окне RESYNC_WINDOW шагов вперёд"),
        ("Блокировка",  f"После {3} неудач вне окна — аккаунт блокируется на {60} сек."),
    ]

    for key, val in lines:
        print(f"  {BOLD}{WHITE}{key:<14}{RESET}  {DIM}{val}{RESET}")
    print()


# ─────────────────────────────────────────────────────────────
#  main
# ─────────────────────────────────────────────────────────────
def main():
    HOST, PORT = "127.0.0.1", 9001

    print(f"\n{BOLD}{CYAN}{'━'*62}{RESET}")
    print(f"{BOLD}{CYAN}   Лабораторная работа №3 — Схема Лэмпорта (OTP){RESET}")
    print(f"{BOLD}{CYAN}   Python  ·  клиент-сервер  ·  TCP{RESET}")
    print(f"{BOLD}{CYAN}{'━'*62}{RESET}\n")

    # Запускаем сервер в фоне
    print(f"{DIM}Запуск TCP-сервера…{RESET}")
    start_server()
    ok(f"Сервер слушает {HOST}:{PORT}\n")

    # Выводим теорию
    show_theory()

    # Запускаем сценарии
    scenario_normal_auth(HOST, PORT)
    scenario_wrong_otp(HOST, PORT)
    scenario_resync(HOST, PORT)
    scenario_lockout(HOST, PORT)
    scenario_chain_exhausted(HOST, PORT)

    hr("═", color=CYAN)
    print(f"{CYAN}{BOLD}  Все сценарии выполнены успешно!{RESET}")
    hr("═", color=CYAN)
    print()


if __name__ == "__main__":
    main()
