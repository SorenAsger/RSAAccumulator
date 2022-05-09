# Prod pow benchmark
# SHOW THESE PROPERLY IN APPENDIX
import time

from gmpy2 import powmod, mpz

from RSAAccumulator import prod_pow, random_prime, create_g, prod, Accumulator
from prime_hash import PrimeHashv2

h = PrimeHashv2(60)
hashes = [mpz(h.prime_hash(i)) for i in range(2**17)]
n = mpz(random_prime(1024) * random_prime(1024))
g = mpz(create_g(n, 2048))
cutoffs = [10**i for i in range(6)]
times = [0 for _ in cutoffs]
reps = 5

def other_pow(base, elements, n, cutoff=0):
    cx = base
    for ele in elements:
        cx = powmod(cx, ele, n)
    return cx

def pure_prod_pow(base, elements, n, cutoff=0):
    return powmod(base, prod(elements), n)

def idk():
    for _ in range(reps):
        for idx, cutoff in enumerate(cutoffs):
            print(cutoff)
            start = time.time()
            pure_prod_pow(g, hashes, n, cutoff=cutoff)
            end = time.time()
            dur = end - start
            print(dur)
            times[idx % len(times)] += dur/reps
    print(times)
# safe prime benchmark


prime_hash = PrimeHashv2(100)
acc = Accumulator(256)
for i in range(40000):
    x = prime_hash.prime_hash(i)
    acc.insert(x)
queries = [prime_hash.prime_hash(i) for i in range(100000, 100010)]
start = time.time()
for query in queries:
    a, d = acc.nonmembershipv2(query)
end = time.time()
print(end - start)
start = time.time()
for query in queries:
    a, d = acc.get_nonmembership(query)
end = time.time()
print(end - start)