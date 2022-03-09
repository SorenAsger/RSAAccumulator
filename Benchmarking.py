import random
import time
from MerkleTree import MerkleTree
from RSAAccumulator import Accumulator, generate_safe_RSA_modulus, PrimeHash, verify_membership, verify_nonmembership
from TestObject import TestObject
from Verification import verify


def MerkleTreeBenchmark(iters, memqueries, nonmemqueries, reps):
    cons_times = []
    memqueries_proof_time = []
    memqueries_verify_time = []
    nonmemqueries_proof_time = []
    nonmemqueries_verify_time = []
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
        witnesses = []
        for i in range(memqueries):
            witness = tree.checkObject(TestObject(i*2))
            witnesses.append(witness)
        end_time = time.time()
        memqueries_proof_time.append(end_time-start_time)
        print(f"Memquery proof {memqueries} time {end_time-start_time}")
        start_time = time.time()
        for i in range(memqueries):
            verify(tree.root.hash, witnesses[i])
        end_time = time.time()
        memqueries_verify_time.append(end_time-start_time)
        print(f"Memquery verify {memqueries} time {end_time-start_time}")
        start_time = time.time()
        nonmem_witnesses = []
        for i in range(nonmemqueries):
            witness = tree.checkObject(TestObject(i*2+1))
            nonmem_witnesses.append(witness)
        end_time = time.time()
        nonmemqueries_proof_time.append(end_time-start_time)
        print(f"Nonmemqueries proof {nonmemqueries} time {end_time-start_time}")
        start_time = time.time()
        for i in range(nonmemqueries):
            verify(tree.root.hash, witnesses[i])
        end_time = time.time()
        nonmemqueries_verify_time.append(end_time-start_time)
        print(f"Nonmemqueries verify {nonmemqueries} time {end_time-start_time}")
    print(f"Avg cons. time {sum(cons_times) / reps}")
    print(f"Avg mem. proof  time {sum(memqueries_proof_time) / reps}")
    print(f"Avg mem. verify time {sum(memqueries_verify_time) / reps}")
    print(f"Avg nonmem. proof time {sum(nonmemqueries_proof_time) / reps}")
    print(f"Avg nonmem. verify time {sum(nonmemqueries_verify_time) / reps}")


def RSABenchmark(iters, memqueries, nonmemqueries, reps, security=2048):
    prime_times = []
    insertion_times = []
    memqueries_prime_time = []
    memqueries_proof_time = []
    memqueries_verify_time = []
    nonmemqueries_proof_time = []
    nonmemqueries_verify_time = []
    nonmemqueries_prime_time = []
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
        print(f"Insertion time {end_time-start_time}")
        start_time = time.time()
        mem_witnesses = []
        mem_primes = []
        for i in range(memqueries):
            mem_primes.append(prime_hash.prime_hash(i * 2))
        end_time = time.time()
        memqueries_prime_time.append(end_time - start_time)
        print(f"Memquery {memqueries} prime time {end_time-start_time}")
        start_time = time.time()
        for i in range(memqueries):
            xprime = mem_primes[i]
            witness = acc.get_membership(xprime)
            mem_witnesses.append(witness)
        end_time = time.time()
        print(f"Memquery {memqueries} proof time {end_time-start_time}")
        memqueries_proof_time.append(end_time-start_time)
        start_time = time.time()
        for i in range(memqueries):
            xprime = mem_primes[i]
            witness = mem_witnesses[i]
            assert verify_membership(xprime, witness, acc.acc, acc.n)
        end_time = time.time()
        memqueries_verify_time.append(end_time-start_time)
        print(f"Memquery {memqueries} verify time {end_time-start_time}")
        start_time = time.time()
        prime_hashes = []
        for i in range(nonmemqueries):
            xprime = prime_hash.prime_hash(i * 2 + 1)
            prime_hashes.append(xprime)
        end_time = time.time()
        prime_time = end_time - start_time
        print(f"Nonmemquery prime time {prime_time}")
        nonmemqueries_prime_time.append(prime_time)

        start_time = time.time()
        nonmem_witnesses = []
        for i in range(nonmemqueries):
            xprime = prime_hash.prime_hash(i * 2 + 1)
            a, d = acc.get_nonmembership(xprime)
            nonmem_witnesses.append((a, d))
        end_time = time.time()
        nonmemqueries_proof_time.append(end_time - start_time)
        print(f"Nonmemquery proof time {end_time - start_time}")
        start_time = time.time()
        for i in range(nonmemqueries):
            xprime = prime_hashes[i]
            a, d = nonmem_witnesses[i]
            assert verify_nonmembership(d, a, xprime, acc.acc, acc.n, acc.g)
        end_time = time.time()
        print(f"Nonmemquery verify time {end_time - start_time}")
        nonmemqueries_verify_time.append(end_time-start_time)
        #print(f"Nonmemqueries {nonmemqueries} time {end_time-start_time}")
    print(f"Avg prime_times time {sum(prime_times) / reps}")
    print(f"Avg safe_prime_times time {sum(safe_prime_times) / reps}")
    print(f"Avg ins. time {sum(insertion_times) / reps}")
    print(f"Avg mem. prime time {sum(memqueries_prime_time) / reps}")
    print(f"Avg mem. proof time {sum(memqueries_proof_time) / reps}")
    print(f"Avg mem. verify time {sum(memqueries_verify_time) / reps}")
    print(f"Avg nonmem. prime time {sum(nonmemqueries_prime_time) / reps}")
    print(f"Avg nonmem. proof time {sum(nonmemqueries_proof_time) / reps}")
    print(f"Avg nonmem. verify time {sum(nonmemqueries_verify_time) / reps}")


#MerkleTreeBenchmark(100000, 10000, 10000, 5)
#RSABenchmark(10000, 1000, 1000, 5, security=128)