import hashlib
import math
import random
from math import ceil

import Crypto
from Crypto import Random
import numpy as np
from Crypto.Util import number
from gmpy2 import gmpy2, powmod, mpz, c_div, gcdext, gcd, c_mod, mul


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
        self.elements = []

    def insert(self, x):
        self.acc = powmod(self.acc, x, self.n)
        self.elements.append(x)
        self.u = self.u * x

    def get_membership(self, x):
        return powmod(self.g, c_div(self.u, x), self.n)
        return prod_pow(self.g, set(self.elements).difference([x]), self.n)
        cx = self.g
        for ele in self.elements:
            if ele != x:
                cx = powmod(cx, ele, self.n)
        return cx

    def get_nonmembership(self, x):
        #u = prod(self.elements)
        u = self.u
        cd, bprime, aprime = gcdext(x, u)
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
        b = bprime - k * u
        d = powmod(self.g, -b, self.n)
        return a, d

    def get_bulk_membership(self, L):
        guv = self.g
        # for ele in self.elements - set(L):
        #    guv = powmod(guv, ele, self.n)
        # guv = powmod(self.g, prod(self.elements - set(L)), self.n)
        guv = prod_pow(self.g, set(self.elements) - set(L), self.n)

        def rec_help(to_partition, current_val):
            if len(to_partition) == 1:
                return [current_val]
            split_point = int(len(to_partition) / 2)
            # part_1 = to_partition[:split_point]
            # part_2 = to_partition[split_point:]
            part_1, part_2 = partition(to_partition)
            # product computation can be optimized
            val_1 = prod_pow(current_val, part_2, self.n)
            val_2 = prod_pow(current_val, part_1, self.n)
            # val_1 = powmod(current_val, prod(part_2), self.n)
            # val_2 = powmod(current_val, prod(part_1), self.n)
            if False:
                val_1 = current_val
                val_2 = current_val
                for ele in part_1:
                    val_2 = powmod(val_2, ele, self.n)
                for ele in part_2:
                    val_1 = powmod(val_1, ele, self.n)
            return rec_help(part_1, val_1) + rec_help(part_2, val_2)

        witnesses = rec_help(L, guv)
        return list(zip(L, witnesses))

    def get_bulk_nonmembership(self, L):
        v = prod(L)
        #u = prod(self.elements)
        u = self.u
        cd, bprime, aprime = gcdext(v, u)
        k = c_div(-aprime, v)
        a = aprime + k * v
        b = bprime - k * u
        return a, powmod(self.g, -b, self.n), v

    def nonmembershipv2(self, x):
        _, a1, b1 = gcdext(self.elements[0], x)
        b1 = powmod(self.g, b1, self.n)
        #print(prev_a)
        #print(prev_b)
        #cum_b = mpz(prev_b)
        pr = powmod(self.g, self.elements[0], self.n)
        for ele in self.elements[1:]:
            _, a2, b2 = gcdext(ele, x)
            # minimize a1 * a2 + kx
            # k = -a1 * a2 / x
            k = c_div(-a1 * a2, x)
            # now below should be done in exponent!
            v1 = powmod(pr, a1 * b2 - k * ele, self.n)
            v2 = powmod(b1, b2 * x + a2 * ele, self.n)
            #v3 = powmod(b1, , self.n)
            #v4 = powmod(pr, , self.n)
            gb = (v1 * v2) % self.n
            a1 = a1 * a2 + k * x
            b1 = gb
            #print("gcd", gcd(a1, b1))
            pr = powmod(pr, ele, self.n)
        gmb = powmod(b1, -1, self.n)
        return a1, gmb


def partition(X):
    # This seems faster than slicing?
    split_point = int(len(X) / 2)
    lst1, lst2 = [], []
    for i, x in enumerate(X):
        if i < split_point:
            lst1.append(x)
        else:
            lst2.append(x)
    return lst1, lst2


def prod(X):
    v = mpz(1)
    for x in X:
        v = mul(v, x)
    return v


def prod_pow(base, X, n, cutoff = 1000):
    # Maybe make this a loop instead
    if len(X) <= cutoff:
        return powmod(base, prod(X), n)
    else:
        part_1, part_2 = partition(X)
        return prod_pow(prod_pow(base, part_1, n), part_2, n)


def verify_membership(x, cx, c, n):
    return powmod(cx, x, n) == c


def verify_nonmembership(d, a, x, c, n, g):
    return powmod(c, a, n) == ((powmod(d, x, n) * g) % n)


def verify_bulk_nonmembership(d, a, X, c, n, g, v):
    vprime = prod(X)
    if vprime == v:
        is_divisible = True
    else:
        is_divisible = c_mod(v, vprime) == 0
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
#5, 7, check nonmember of 3
def funk1(x, q, p):
    _, inv1, h1 = gcdext(x, q)
    _, inv2, h2 = gcdext(x, p)
    _, a, b = gcdext(q, p)
    inv = (inv2 * a * q + inv1 * b * p)
    h = (h2 * a + h1 * b)
    return h, inv


def funky(x, q, p, r):
    print("new")
    _, inv1, h1 = gcdext(x, q)
    _, inv2, h2 = gcdext(x, p)
    _, inv3, h3 = gcdext(x, r)
    #inv1 = inv11 % q
    #inv2 = inv22 % p

    #inv2 = pow(x, -1, p)
    _, a, b = gcdext(q, p)
    _, c, d = gcdext(p, r)
    inv = (inv2 * a * q + inv1 * b * p) * d * r + inv3 * c * p
    h = (h2 * a + h1 * b)

    #print(a * q + b * p)
    #print(inv)
    print("test", (inv * x) % (q * p * c))
    print(inv * x)
    print(h1, h2)
    #print(x * inv)
    #print(x * inv1 % q)
    print(a)
    print(b)
    print(x * inv // (q * p))
    #print(x*inv - 4 * 5 * 7)

funky(3, 5, 7, 11)
funky(2, 5, 7, 11)
funky(5, 7, 11)


_, a1, b1 = gcdext(3, 5)
_, a2, b2 = gcdext(3, 7)
_, a3, b3 = gcdext(3, 11)
n = 19
g = 2
a = a1 + a2 + a3
b = b1 + b2 + b3
u = 5 * 7 * 11
c = pow(g, u, n)
ca = pow(c, a, n)
d = pow(g, -b, n)
print(ca)
print(pow(d, 3, n))
"""

def nonmem(x, elements, n):
    g = 4
    _, a1, b1 = gcdext(elements[0], x)
    #gb = powmod(g, prev_a, n)
    #print(prev_a)
    #print(prev_b)
    prev_ele = elements[0]
    #cum_b = mpz(prev_b)
    for ele in elements[1:]:
        _, a2, b2 = gcdext(ele, x)
        v1 = a1 * b2 * prev_ele
        v2 = b1 * b2 * 7
        v3 = b1 * a2 * 13
        cum = v1 + v2 + v3
        a1 = a1 * a2
        b1 = cum_b
        prev_ele = ele
    gmb = powmod(gb, 1-b1, n)
    return a1, gmb, prev_b

#a, gmb, b = (nonmem(7, [11, 13], 31))

_, a1, b1 = gcdext(11, 7)
_, a2, b2 = gcdext(13, 7)
_, a3, b3 = gcdext(17, 7)
v1 = a1 * b2 * 11
v2 = b1 * b2 * 7
v3 = b1 * a2 * 13
cum = v1 + v2 + v3
a1p = a1 * a2
b1p = cum
v1p = a1p * b3 * 11 * 13
v2p = b1p * b3 * 7
v3p = b1p * a3 * 17
cump = v1p + v2p + v3p
print(a1p * a3 * 11 * 13 * 17 + 7 * cump)

#print(a, b)
#print(11 * 13 * a + b * 7)