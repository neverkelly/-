import secrets
import math


def is_prime(n):
    if n < 2:
        return False

    if n % 2 == 0:
        return n == 2

    d = 3

    while d * d <= n:
        if n % d == 0:
            return False
        d += 2

    return True


def generate_prime(bits=16):
    while True:
        p = secrets.randbits(bits)

        if p % 2 == 0:
            p += 1

        while not is_prime(p):
            p += 2

        return p


def generate_keys():
    p = generate_prime()
    q = generate_prime()

    while p == q:
        q = generate_prime()

    n = p * q

    while True:
        s = secrets.randbelow(n - 2) + 2

        if math.gcd(s, n) == 1:
            break

    v = pow(s, 2, n)

    return n, s, v