import hashlib
import random
from math import ceil

from Crypto.Util import number
from gmpy2 import gmpy2


class PrimeHashv2:

    def __init__(self, security=128):
        self.security = security
        self.prime_map = {}
        self.p = number.getPrime(security)
        self.b = random.randint(2 ** (security - 1), 2 ** security) % self.p
        self.a = random.randint(2 ** (security - 1), 2 ** security) % self.p

    def random_oracle(self, x):
        m = hashlib.sha256()
        m.update(x.to_bytes(len(bin(x)), 'big'))

        num = int.from_bytes(m.digest(), 'big')
        num = num % (2 ** self.security)
        return num

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
        h_d = (h + i) * self.a
        ax_d = h_d * self.p
        return ax_d // self.a + x

    def prime_hash(self, x):
        """
        :param x: element to hash
        :return: a prime as hash value
        """
        x = x % self.p
        hash_val = self.universal_hash(x)
        hash_val_before_mod = (x * self.a + self.b)
        h, y = divmod(hash_val_before_mod, self.p)
        i = ceil(x / self.p - h)
        while True:
            num = self.get_pre_image(x, h, i)
            assert self.universal_hash(num) == hash_val
            if number.isPrime(num):
                self.prime_map[num] = len(bin(num))
                return num
