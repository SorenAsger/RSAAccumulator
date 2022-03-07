import random
import time

from MerkleTree import MerkleTree
from RSAAccumulator import Accumulator, generate_safe_RSA_modulus, PrimeHash
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
        print(f"Construction time{end_time-start_time}")
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


def RSABenchmark(iters, memqueries, nonmemqueries, reps):
    prime_times = []
    cons_times = []
    memqueries_time = []
    nonmemqueries_time = []
    safe_prime_times = []
    for j in range(reps):
        prime_hash = PrimeHash(2048)
        start_time = time.time()
        rsa_modulus = generate_safe_RSA_modulus()
        end_time = time.time()
        safe_prime_times.append(end_time - start_time)
        test_objects = []
        for i in range(iters):
            test_objects.append(TestObject(i*2))
        acc = Accumulator()
        for i in range(2, iters):
            tree.insert(test_objects[i])
        end_time = time.time()
        cons_times.append(end_time - start_time)
        print(f"Construction time{end_time-start_time}")
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



MerkleTreeBenchmark(100000, 10000, 10000, 10)