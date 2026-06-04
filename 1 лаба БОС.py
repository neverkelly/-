class FastBBS:
    def __init__(self, p, q, seed):
        self.n = p * q
        self.state = (seed * seed) % self.n

    def next_value(self):
        self.state = (self.state * self.state) % self.n

        # берем не 1 бит, а 16 младших бит
        return self.state & 0xFFFF

    def next_int(self):
        # XOR-смешивание (whitening)
        a = self.next_value()
        b = self.next_value()
        c = self.next_value()

        return a ^ (b << 5) ^ (c << 10)


# Пример
if __name__ == "__main__":
    p = 499
    q = 547
    seed = 159201

    gen = FastBBS(p, q, seed)

    for _ in range(10):
        print(gen.next_int())