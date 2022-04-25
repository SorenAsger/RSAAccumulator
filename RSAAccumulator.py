import hashlib
import math
import random
from math import ceil

import Crypto
from Crypto import Random
import numpy as np
from Crypto.Util import number
from gmpy2 import gmpy2, powmod, mpz, c_div, gcdext, gcd, c_mod


def random_prime(bits=2048):
    return number.getPrime(bits)


def random_safe_prime(bits=2048):
    while True:
        p = random_prime(bits)
        pprime = 2 * p + 1
        if gmpy2.is_prime(pprime):
            return p, pprime
        pprime = (p - 1) // 2
        if gmpy2.is_prime(pprime):
            return pprime, p


def generate_safe_RSA_modulus(bits=2048):
    p, pp = random_safe_prime(bits // 2)
    q, qp = random_safe_prime(bits // 2)
    return p * q


class PrimeHashv2:

    def __init__(self, security=128):
        self.security = security
        self.prime_map = {}
        self.p = number.getPrime(security)
        self.b = random.randint(2 ** (security - 1), 2 ** security) % self.p
        self.a = random.randint(2 ** (security - 1), 2 ** security) % self.p
        # print(self.byts)
        # print(len(self.byts))

    def random_oracle(self, x):
        m = hashlib.sha256()
        # print(self.b)
        m.update(x.to_bytes(len(bin(x)), 'big'))
        # m.update(self.byts)

        num = int.from_bytes(m.digest(), 'big')
        num = num % (2 ** self.security)
        return num
        # return (x * self.a + self.b) % self.p

    def prime_hash(self, x):
        # Proving any sort of security of this seems impossible
        # We essentially apply a universal hash and then select next prime
        # Seems quite impossible to make any guarantees on collisions here
        # Maliciously finding collisions is quite easy
        # hashval = int(gmpy2.next_prime(self.universal_hash(x)))
        hashval = int(gmpy2.next_prime(self.random_oracle(x)))
        self.prime_map[hashval] = len(bin(hashval))
        return hashval


class PrimeHash:

    def __init__(self, security=128):
        self.prime_map = {}
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
        return ((x + i * self.p) - self.b) / self.a

    def inv_universal_hashv2(self, y, h, i):
        return ((y + h * self.p) - self.b) + self.a * self.p * i / self.a

    def get_pre_image(self, x, h, i):
        # print("preimg")
        h_d = (h + i) * self.a
        # print(x)
        # print(h_d)
        # print(self.a)
        ax_d = h_d * self.p
        # print(int(ax_d/self.a))
        # print(ax_d//self.a)
        # print(self.p)
        q, r = divmod(ax_d, self.a)
        # print(q, r)
        return ax_d // self.a + x

    def prime_hash(self, x):
        """
        :param x: element to hash
        :return: a prime as hash value
        """
        x = x % self.p
        hash_val = self.universal_hash(x)
        # print("start")
        # print(x)
        # print(hash_val)
        hash_val_before_mod = (x * self.a + self.b)
        h, y = divmod(hash_val_before_mod, self.p)
        pre_img = self.get_pre_image(x, h, 1)
        i = ceil(x / self.p - h)
        # i = 0
        # print("init", i)
        # print(int(pre_img))
        # print(int(self.p))
        # print("uni hash")
        # print(self.universal_hash(pre_img))
        # print(self.universal_hash(x + self.p))
        # print(self.inv_universal_hashv2(y, h, 0))
        # print(h)
        # print(self.universal_hash(self.inv_universal_hash(hash_val, 1)))
        while True:
            # print(i)
            # print(self.inv_universal_hash(hash_val, 1))
            # num = int(self.inv_universal_hashv2(y, h, i))
            num = self.get_pre_image(x, h, i)
            # print("preimg", num)
            # print("unihash", self.universal_hash(num))
            assert self.universal_hash(num) == hash_val
            if number.isPrime(num):
                self.prime_map[num] = len(bin(num))
                # print("found prime")
                # print(self.prime_map)
                return num
            i += 1
            # below is just to notify if it takes too many iterations
            if i % 10000 == 0 and i > 1:
                print("n", num)
                print("x", x)
                print("a", self.a)
                print("b", self.b)
                print("p", self.p)
                print("hval", hash_val)
                print("h", h)
                print(f"Failure: {i}")
                exit(0)


def create_generator(n, security):
    a = random.randint(0, 2 ** security)
    if gcd(a - 1, n) == 1 and gcd(a + 1, n) == 1 and gcd(a, n) == 1:
        return a ** 2 % n
    return create_generator(n, security)


class Accumulator:

    def __init__(self, security, rsa_modulus=None):
        if rsa_modulus is None:
            self.n = mpz(generate_safe_RSA_modulus(security))
        else:
            self.n = rsa_modulus
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
        cd, bprime, aprime = gcdext(x, self.u)
        # cd, bprime, aprime = gcdext(x, self.u)
        k = c_div(-aprime, x)
        a = aprime + k * x
        # want aprime = -k * x
        # k = aprime/-x
        # We have k >= aprime/-x
        # Thus -k * x <= aprime
        # Which implies 0 <= aprime + k*x
        # Want to minimize witness size, we want to minimize aprime + k*x, obv if aprime = - kx?, so
        # find k = -aprime x
        b = bprime - k * self.u
        d = powmod(self.g, -b, self.n)
        return a, d

    def get_bulk_membership(self, L):
        v = prod(L)
        guv = powmod(self.g, c_div(self.u, v), self.n)

        def rec_help(to_partition, current_val):
            if len(to_partition) == 1:
                return [current_val]
            split_point = int(len(to_partition) / 2)
            part_1 = to_partition[:split_point]
            part_2 = to_partition[split_point:]
            # product computation can be optimized
            prod_1 = prod(part_1)
            prod_2 = prod(part_2)
            val_1 = powmod(current_val, prod_2, self.n)
            val_2 = powmod(current_val, prod_1, self.n)
            return rec_help(part_1, val_1) + rec_help(part_2, val_2)

        witnesses = rec_help(L, guv)
        return list(zip(L, witnesses))

    def get_bulk_nonmembership(self, L):
        v = prod(L)
        cd, bprime, aprime = gcdext(v, self.u)
        k = c_div(-aprime, v)
        a = aprime + k * v
        b = bprime - k * self.u
        return a, powmod(self.g, -b, self.n), v


def prod(X):
    v = mpz(1)
    for x in X:
        v = v * x
    return v


def verify_membership(x, cx, c, n):
    return powmod(cx, x, n) == c


def verify_nonmembership(d, a, x, c, n, g):
    return powmod(c, a, n) == ((powmod(d, x, n) * g) % n)


def verify_bulk_nonmembership(d, a, X, c, n, g, v):
    is_divisible = c_mod(v, prod(X)) == 0
    # is_divisible = True
    return powmod(c, a, n) == ((powmod(d, v, n) * g) % n) and is_divisible


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
