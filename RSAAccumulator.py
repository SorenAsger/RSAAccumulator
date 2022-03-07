import random
from math import gcd

from Crypto.Util import number


def random_prime(bits=2048):
    return number.getPrime(bits)


def random_safe_prime(bits=2048):
    while True:
        p = random_prime(bits)
        pprime = 2 * p + 1
        if number.isPrime(pprime):
            return p, pprime
        pprime = (p - 1) // 2
        if number.isPrime(pprime):
            return pprime, p


def generate_safe_RSA_modulus(bits=2048):
    p, pp = random_safe_prime(bits)
    q, qp = random_safe_prime(bits)
    return p * q


class PrimeHash():

    def __init__(self, bits):
        self.a = random.randint(0, 2 ** bits)
        self.b = random.randint(0, 2 ** bits)
        self.p = number.getPrime(bits)

    def universal_hash(self, x):
        return (x * self.a + self.b % self.p)


    def inv_universal_hash(self, x, i):
        return int(x // self.a - self.b + i * self.p)


    def prime_hash(self, x):
        i = 0
        hash_val = self.universal_hash(x)
        while True:
            num = self.inv_universal_hash(hash_val, i)
            if number.isPrime(num):
                return num
            i += 1


def create_generator(n, security):
    a = random.randint(0, 2 ** security)
    if gcd(a - 1, n) == 1 and gcd(a + 1, n) == 1 and gcd(a, n) == 1:
        return a ** 2 % n
    return create_generator(n, security)


class Accumulator:

    def __init__(self, security):
        self.n = generate_safe_RSA_modulus(security)
        self.g = create_generator(self.n, security)
        self.acc = self.g
        self.u = 1

    def insert(self, x):
        self.acc = pow(self.acc, x, self.n)
        self.u = self.u * x

    def get_membership(self, x):
        cx = pow(self.g, int(self.u // x), self.n)
        return cx

    def get_nonmembership(self, x):
        #cd, aprime, bprime = gcdExtended(x, self.u)
        cd, bprime, aprime = gcdExtended(x, self.u)
        k = 1
        if aprime < -x:
            k = int(-aprime // x) + 1
        a = aprime + k * x
        b = bprime - k * self.u
        d = pow(self.g, -b, self.n)
        return a, d


def verify_membership(x, cx, c, n):
    return pow(cx, x, n) == c


def verify_nonmembership(d, a, x, c, n, g):
    return pow(c, a, n) == ((pow(d, x, n) * g) % n)


def gcdExtended(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = gcdExtended(b % a, a)

    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


"""
print(prime_hash(234592))
print(random_safe_prime())
test_n = generate_safe_RSA_modulus()
acc = Accumulator(test_n)
primevals =[]
for i in range(100):
    primevals.append(prime_hash(i))

for i in range(100):
    acc.insert(primevals[i])

acc_val = acc.acc
mproof = acc.get_membership(primevals[0])
a, d = acc.get_nonmembership(primevals[0] + 1)
a2, d2 = acc.get_nonmembership(prime_hash(102))
print(verify_membership(primevals[0], mproof, acc_val, test_n))
print(verify_membership(primevals[0], mproof, acc_val, test_n))
print(verify_nonmembership(d, a, primevals[0] + 2, acc_val, test_n, acc.g))
print(verify_nonmembership(d2, a2, prime_hash(102), acc_val, test_n, acc.g))
"""