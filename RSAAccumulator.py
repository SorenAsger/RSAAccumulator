import hashlib
import random

import Crypto
from Crypto import Random
from Crypto.Util import number
from gmpy2 import gmpy2, powmod, mpz, c_div, gcdext, gcd


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
    p, pp = random_safe_prime(bits // 2)
    q, qp = random_safe_prime(bits // 2)
    return p * q


class PrimeHashv2:

    def __init__(self, security=128):
        self.p = number.getPrime(security)
        self.b = random.randint(2 ** (security - 1), 2 ** security) % self.p
        self.a = random.randint(2 ** (security - 1), 2 ** security) % self.p

    def universal_hash(self, x):
        return (x * self.a + self.b) % self.p

    def prime_hash(self, x):
        # Proving any sort of security of this seems impossible
        # We essentially apply a universal hash and then select next prime
        # Seems quite impossible to make any guarantees on collisions here
        # Maliciously finding collisions is quite easy
        return int(gmpy2.next_prime(self.universal_hash(x)))


class PrimeHash:

    def __init__(self, security=128):
        self.p = number.getPrime(security)
        self.a = random.randint(2 ** (security - 1), 2 ** security) % self.p
        self.b = random.randint(2 ** (security - 1), 2 ** security) % self.p

    def universal_hash(self, x):
        # Seems to be some issue here that gives collisions, might be related to the inverse computation
        return (x * self.a + self.b) % self.p

    def inv_universal_hash(self, x, i):
        """
        :param x: element to compute inverse of
        :param i: i'th inverse to compute
        :return: the i'th inverse of x
        """
        return int(x // self.a - self.b + i * self.p)

    def prime_hash(self, x):
        """
        :param x: element to hash
        :return: a prime as hash value
        """
        i = 0
        hash_val = self.universal_hash(x)
        while True:
            num = self.inv_universal_hash(hash_val, i)
            if number.isPrime(num):
                return num
            i += 1
            # below is just to notify if it takes too many iterations
            if i % 1000 == 0 and i > 1:
                print(f"Failure: {i}")


def create_generator(n, security):
    a = random.randint(0, 2 ** security)
    if gcd(a - 1, n) == 1 and gcd(a + 1, n) == 1 and gcd(a, n) == 1:
        return a ** 2 % n
    return create_generator(n, security)


class Accumulator:

    def __init__(self, security):
        self.n = mpz(generate_safe_RSA_modulus(security))
        self.g = mpz(create_generator(self.n, security))
        self.acc = self.g
        self.u = mpz(1)

    def insert(self, x):
        self.acc = powmod(self.acc, x, self.n)
        self.u = self.u * x

    def get_membership(self, x):
        cx = powmod(self.g, c_div(self.u, x), self.n)
        return cx

    def get_nonmembership(self, x):
        # cd, aprime, bprime = gcdExtended(x, self.u)
        cd, bprime, aprime = gcdext(x, self.u)
        k = 1
        if aprime < -x:
            k = c_div(-aprime, x) + 1
        a = aprime + k * x
        b = bprime - k * self.u
        d = powmod(self.g, -b, self.n)
        return a, d


def verify_membership(x, cx, c, n):
    return powmod(cx, x, n) == c


def verify_nonmembership(d, a, x, c, n, g):
    return powmod(c, a, n) == ((powmod(d, x, n) * g) % n)



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

