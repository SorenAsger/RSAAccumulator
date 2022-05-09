import random

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


def create_g(n, security):
    a = random.randint(0, 2 ** security)
    if gcd(a - 1, n) == 1 and gcd(a + 1, n) == 1 and gcd(a, n) == 1:
        return a ** 2 % n
    return create_g(n, security)


class Accumulator:

    def __init__(self, security, rsa_modulus=None):
        if rsa_modulus is None:
            self.n = mpz(generate_safe_RSA_modulus(security))
        else:
            self.n = rsa_modulus
        self.g = mpz(create_g(self.n, security))
        self.acc = self.g
        self.u = mpz(1)
        self.elements = []

    def insert(self, x):
        self.acc = powmod(self.acc, x, self.n)
        self.elements.append(x)
        self.u = self.u * x

    def get_membership(self, x):
        return powmod(self.g, c_div(self.u, x), self.n)

    def get_nonmembership(self, x):
        # u = prod(self.elements)
        u = self.u
        cd, aprime, bprime = gcdext(u, x)
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
        guv = prod_pow(self.g, set(self.elements) - set(L), self.n)

        def rec_help(to_partition, current_val):
            if len(to_partition) == 1:
                return [current_val]
            part_1, part_2 = partition(to_partition)
            val_1 = prod_pow(current_val, part_2, self.n)
            val_2 = prod_pow(current_val, part_1, self.n)
            return rec_help(part_1, val_1) + rec_help(part_2, val_2)

        witnesses = rec_help(L, guv)
        return list(zip(L, witnesses))

    def get_bulk_nonmembership(self, L):
        v = prod(L)
        u = self.u
        cd, bprime, aprime = gcdext(v, u)
        k = c_div(-aprime, v)
        a = aprime + k * v
        b = bprime - k * u
        return a, powmod(self.g, -b, self.n), v


class AccumulatorNoU(Accumulator):

    def __init__(self, security, rsa_modulus=None):
        super(AccumulatorNoU, self).__init__(security, rsa_modulus)
        self.elements = []

    def insert(self, x):
        self.acc = powmod(self.acc, x, self.n)
        self.elements.append(x)

    def get_membership(self, x):
        prod_pow(self.g, set(self.elements).difference([x]), self.n)

    def get_nonmembership(self, x):
        _, a1, b1 = gcdext(self.elements[0], x)
        b1 = powmod(self.g, b1, self.n)
        pr = powmod(self.g, self.elements[0], self.n)
        for ele in self.elements[1:]:
            _, a2, b2 = gcdext(ele, x)
            # minimize a1 * a2 + kx
            # k = -a1 * a2 / x
            k = c_div(-a1 * a2, x)
            # g^b mod n
            v1 = powmod(pr, a1 * b2 - k * ele, self.n)
            v2 = powmod(b1, b2 * x + a2 * ele, self.n)
            gb = (v1 * v2) % self.n
            a1 = a1 * a2 + k * x
            b1 = gb
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


def prod_pow(base, X, n, cutoff=10):
    # Maybe make this a loop instead
    # This seems faster than it should - not quite sure why
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
