import unittest

from RSAAccumulator import Accumulator, verify_membership, verify_nonmembership, verify_bulk_nonmembership, \
    AccumulatorNoU
from prime_hash import RandomOraclePrimeHash


class RSAAccumulatorTest(unittest.TestCase):

    def test_membership(self):
        prime_hash = RandomOraclePrimeHash(100)
        acc = Accumulator(256)
        for i in range(250):
            x = prime_hash.prime_hash(i)
            acc.insert(x)
        queries = [prime_hash.prime_hash(i) for i in range(100, 125)]
        for query in queries:
            cx = acc.get_membership(query)
            assert verify_membership(query, cx, acc.acc, acc.n)

    def test_membership_no_U(self):
        prime_hash = RandomOraclePrimeHash(100)
        acc = AccumulatorNoU(256)
        for i in range(250):
            x = prime_hash.prime_hash(i)
            acc.insert(x)
        queries = [prime_hash.prime_hash(i) for i in range(100, 125)]
        for query in queries:
            cx = acc.get_membership(query)
            assert verify_membership(query, cx, acc.acc, acc.n)


    def test_bulk_membership(self):
        prime_hash = RandomOraclePrimeHash(100)
        acc = Accumulator(256)
        for i in range(1000):
            x = prime_hash.prime_hash(i)
            acc.insert(x)
        bulk = [prime_hash.prime_hash(i) for i in range(1000)]
        witnesses = acc.get_bulk_membership(bulk)
        assert len(witnesses) == len(bulk)
        for x, cx in witnesses:
            assert verify_membership(x, cx, acc.acc, acc.n)

    def test_non_membership(self):
        prime_hash = RandomOraclePrimeHash(100)
        acc = Accumulator(256)
        for i in range(250):
            x = prime_hash.prime_hash(i)
            acc.insert(x)
        queries = [prime_hash.prime_hash(i) for i in range(250, 275)]
        for query in queries:
            a, d = acc.get_nonmembership(query)
            assert verify_nonmembership(d, a, query, acc.acc, acc.n, acc.g)

    def test_bulk_nonmembership(self):
        prime_hash = RandomOraclePrimeHash(100)
        acc = Accumulator(256)
        for i in range(25):
            x = prime_hash.prime_hash(i)
            acc.insert(x)
        bulk = [prime_hash.prime_hash(i) for i in range(25, 35)]
        a, d, v = acc.get_bulk_nonmembership(bulk)
        assert verify_bulk_nonmembership(d, a, bulk, acc.acc, acc.n, acc.g, v)

    def test_non_membership_no_U(self):
        prime_hash = RandomOraclePrimeHash(100)
        acc = AccumulatorNoU(256)
        for i in range(250):
            x = prime_hash.prime_hash(i)
            acc.insert(x)
        queries = [prime_hash.prime_hash(i) for i in range(250, 275)]
        for query in queries:
            a, d = acc.get_nonmembership(query)
            assert verify_nonmembership(d, a, query, acc.acc, acc.n, acc.g)

if __name__ == '__main__':
    unittest.main()
