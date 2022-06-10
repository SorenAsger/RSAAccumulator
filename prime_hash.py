import hashlib
import random
from math import ceil

from Crypto.Util import number
from gmpy2 import gmpy2


class RandomOraclePrimeHash:

    def __init__(self, security=128):
        self.security = security
        self.prime_map = {}

    def random_oracle(self, x):
        m = hashlib.sha256()
        m.update(x.to_bytes(len(bin(x)), 'big'))
        num = int.from_bytes(m.digest(), 'big')
        num = num % (2 ** self.security)
        return num

    def prime_hash(self, x):
        hashval = int(gmpy2.next_prime(self.random_oracle(x)))
        self.prime_map[hashval] = len(bin(hashval))
        return hashval


class PrimeHash:

    def __init__(self, security=128):
        self.prime_map = {}
        self.p = number.getPrime(security)
        self.a = random.randint(2 ** (security - 1), 2 ** security) % self.p
        self.b = random.randint(2 ** (security - 1), 2 ** security) % self.p


    def get_pre_image(self, x, h, i):
        return (h + i) * self.p + x


    def universal_hash(self, x):
        return (self.a * x + self.b) % self.p

    def prime_hash(self, x):
        """
        :param x: element to hash
        :return: a prime as hash value
        """
        x = x % self.p
        hash_val_before_mod = (x * self.a + self.b)
        #h_val = hash_val_before_mod % self.p
        h, y = divmod(hash_val_before_mod, self.p)
        i = ceil(-x / self.p - h)
        while True:
            num = self.get_pre_image(x, h, i)
            #assert self.universal_hash(num) == h_val
            if number.isPrime(num):
                self.prime_map[num] = len(bin(num))
                return num
            i += 1
