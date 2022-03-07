import random
import time
from MerkleTree import MerkleTree
from RSAAccumulator import Accumulator, generate_safe_RSA_modulus, PrimeHash, verify_membership, verify_nonmembership
from TestObject import TestObject
from Verification import verify


def MerkleTreeBenchmark(iters, memqueries, nonmemqueries, reps):
    cons_times = []
    memqueries_time = []
    nonmemqueries_time = []
    for j in range(reps):
        test_objects = []
        for i in range(iters):
            test_objects.append(TestObject(i*2))
        random.shuffle(test_objects)
        start_time = time.time()
        tree = MerkleTree(test_objects[0], test_objects[1])
        for i in range(2, iters):
            tree.insert(test_objects[i])
        end_time = time.time()
        cons_times.append(end_time - start_time)
        print(f"Construction time {end_time-start_time}")
        start_time = time.time()
        for i in range(memqueries):
            witness = tree.checkObject(TestObject(i*2))
            verify(tree.root.hash, witness)
        end_time = time.time()
        memqueries_time.append(end_time-start_time)
        print(f"Memquery {memqueries} time {end_time-start_time}")
        start_time = time.time()
        for i in range(nonmemqueries):
            witness = tree.checkObject(TestObject(i*2+1))
            verify(tree.root.hash, witness)
        end_time = time.time()
        nonmemqueries_time.append(end_time-start_time)
        print(f"Nonmemqueries {nonmemqueries} time {end_time-start_time}")
    print(f"Avg cons. time {sum(cons_times) / reps}")
    print(f"Avg mem. time {sum(memqueries_time) / reps}")
    print(f"Avg nonmem. time {sum(nonmemqueries_time) / reps}")


def RSABenchmark(iters, memqueries, nonmemqueries, reps, security=2048):
    prime_times = []
    insertion_times = []
    memqueries_time = []
    nonmemqueries_time = []
    safe_prime_times = []
    for j in range(reps):
        prime_hash = PrimeHash(security)
        start_time = time.time()
        acc = Accumulator(security)
        end_time = time.time()
        safe_prime_times.append(end_time - start_time)
        print(f"Safe prime time {end_time-start_time}")
        prime_objects = []
        start_time = time.time()
        for i in range(iters):
            prime_objects.append(prime_hash.prime_hash(i*2))
        end_time = time.time()
        print(f"Prime time {end_time-start_time}")
        prime_times.append(end_time - start_time)
        start_time = time.time()
        for i in range(iters):
            acc.insert(prime_objects[i])
        end_time = time.time()
        insertion_times.append(end_time - start_time)
        print(f"Insetion time {end_time-start_time}")
        start_time = time.time()
        for i in range(memqueries):
            xprime = prime_hash.prime_hash(i * 2)
            witness = acc.get_membership(xprime)
            assert verify_membership(xprime, witness, acc.acc, acc.n)
        end_time = time.time()
        memqueries_time.append(end_time-start_time)
        print(f"Memquery {memqueries} time {end_time-start_time}")
        start_time = time.time()
        for i in range(nonmemqueries):
            xprime = prime_hash.prime_hash(i * 2 + 1)
            a, d = acc.get_nonmembership(xprime)
            assert verify_nonmembership(d, a, xprime, acc.acc, acc.n, acc.g)
        end_time = time.time()
        nonmemqueries_time.append(end_time-start_time)
        print(f"Nonmemqueries {nonmemqueries} time {end_time-start_time}")
    print(f"Avg prime_times time {sum(prime_times) / reps}")
    print(f"Avg safe_prime_times time {sum(safe_prime_times) / reps}")
    print(f"Avg ins. time {sum(insertion_times) / reps}")
    print(f"Avg mem. time {sum(memqueries_time) / reps}")
    print(f"Avg nonmem. time {sum(nonmemqueries_time) / reps}")


#MerkleTreeBenchmark(10000, 1000, 1000, 5)
#RSABenchmark(10000, 1000, 1000, 5, security=128)