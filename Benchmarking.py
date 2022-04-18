import random
import time
from MerkleTree import MerkleTree
from RSAAccumulator import Accumulator, generate_safe_RSA_modulus, PrimeHash, verify_membership, verify_nonmembership, \
    PrimeHashv2
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
            test_objects.append(TestObject(i * 2))
        random.shuffle(test_objects)
        start_time = time.time()
        tree = MerkleTree(test_objects[0], test_objects[1])
        for i in range(2, iters):
            tree.insert(test_objects[i])
        end_time = time.time()
        cons_times.append(end_time - start_time)
        print(f"Construction time {end_time - start_time}")
        start_time = time.time()
        witnesses = []
        for i in range(memqueries):
            witness = tree.checkObject(TestObject(i * 2))
            witnesses.append(witness)
        end_time = time.time()
        memqueries_proof_time.append(end_time - start_time)
        print(f"Memquery proof {memqueries} time {end_time - start_time}")
        start_time = time.time()
        for i in range(memqueries):
            verify(tree.root.hash, witnesses[i])
        end_time = time.time()
        memqueries_verify_time.append(end_time - start_time)
        print(f"Memquery verify {memqueries} time {end_time - start_time}")
        start_time = time.time()
        nonmem_witnesses = []
        for i in range(nonmemqueries):
            witness = tree.checkObject(TestObject(i * 2 + 1))
            nonmem_witnesses.append(witness)
        end_time = time.time()
        nonmemqueries_proof_time.append(end_time - start_time)
        print(f"Nonmemqueries proof {nonmemqueries} time {end_time - start_time}")
        start_time = time.time()
        for i in range(nonmemqueries):
            verify(tree.root.hash, witnesses[i])
        end_time = time.time()
        nonmemqueries_verify_time.append(end_time - start_time)
        print(f"Nonmemqueries verify {nonmemqueries} time {end_time - start_time}")
    print(f"Avg cons. time {sum(cons_times) / reps}, avg per query {sum(memqueries_verify_time) / (reps * iters)} ")
    print(
        f"Avg mem. proof  time {sum(memqueries_proof_time) / reps}, avg per query {sum(memqueries_proof_time) / (reps * memqueries)}")
    print(
        f"Avg mem. verify time {sum(memqueries_verify_time) / reps} avg per query {sum(memqueries_verify_time) / (reps * memqueries)}")
    print(
        f"Avg nonmem. proof time {sum(nonmemqueries_proof_time) / reps}, avg per query {sum(nonmemqueries_proof_time) / (reps * nonmemqueries)}")
    print(
        f"Avg nonmem. verify time {sum(nonmemqueries_verify_time) / reps} avg per query {sum(nonmemqueries_verify_time) / (reps * nonmemqueries)}")


def RSABenchmark(iters, memqueries, nonmemqueries, reps, prime_hash, rsa_modulus, security=2048):
    prime_times = []
    insertion_times = []
    memqueries_prime_time = []
    memqueries_proof_time = []
    memqueries_verify_time = []
    memwitness_size = []
    nonmemqueries_proof_time = []
    nonmemqueries_verify_time = []
    nonmemqueries_prime_time = []
    safe_prime_times = []
    nonmemwitness_size = []
    for j in range(reps):
        start_time = time.time()
        acc = Accumulator(security, rsa_modulus)
        end_time = time.time()
        safe_prime_times.append(end_time - start_time)
        print(f"Safe prime time {end_time - start_time}")
        prime_objects = []
        start_time = time.time()
        for i in range(iters):
            prime_objects.append(prime_hash.prime_hash(i * 2))
        end_time = time.time()
        print(f"Prime time {end_time - start_time}")
        prime_times.append(end_time - start_time)
        start_time = time.time()
        for i in range(iters):
            acc.insert(prime_objects[i])
        end_time = time.time()
        insertion_times.append(end_time - start_time)
        print(f"Insertion time {end_time - start_time}")
        start_time = time.time()
        mem_witnesses = []
        mem_primes = []
        for i in range(memqueries):
            mem_primes.append(prime_hash.prime_hash(i * 2))
        end_time = time.time()
        memqueries_prime_time.append(end_time - start_time)
        print(f"Memquery {memqueries} prime time {end_time - start_time}")
        start_time = time.time()
        for i in range(memqueries):
            xprime = mem_primes[i]
            witness = acc.get_membership(xprime)
            mem_witnesses.append(witness)
            memwitness_size.append(len(bin(witness)))
        end_time = time.time()
        print(f"Memquery {memqueries} proof time {end_time - start_time}")
        memqueries_proof_time.append(end_time - start_time)
        start_time = time.time()
        for i in range(memqueries):
            xprime = mem_primes[i]
            witness = mem_witnesses[i]
            assert verify_membership(xprime, witness, acc.acc, acc.n)
        end_time = time.time()
        memqueries_verify_time.append(end_time - start_time)
        print(f"Memquery {memqueries} verify time {end_time - start_time}")
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
            nonmemwitness_size.append(len(bin(a)) + len(bin(d)))
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
        nonmemqueries_verify_time.append(end_time - start_time)
        hash_queries = len(prime_hash.prime_map)
        print("hash queries")
        print(sum(prime_hash.prime_map.values()) / hash_queries)
        print(hash_queries)
        print(iters + nonmemqueries)
        assert hash_queries == (iters + nonmemqueries)
        # print(f"Nonmemqueries {nonmemqueries} time {end_time-start_time}")
    print(f"Avg prime_times time {sum(prime_times) / reps} avg. per query {sum(prime_times) / (reps * iters)}")
    print(f"Avg safe_prime_times time {sum(safe_prime_times) / reps}")
    print(f"Avg ins. time {sum(insertion_times) / reps} and avg. per query {sum(insertion_times) / (reps * iters)}")
    print(
        f"Avg mem. prime time {sum(memqueries_prime_time) / reps} avg. per query {sum(memqueries_prime_time) / (reps * memqueries)}")
    print(
        f"Avg mem. proof time {sum(memqueries_proof_time) / reps} avg. per query {sum(memqueries_proof_time) / (reps * memqueries)}")
    print(
        f"Avg mem. verify time {sum(memqueries_verify_time) / reps} avg. per query {sum(memqueries_verify_time) / (reps * memqueries)}")
    print(
        f"Avg nonmem. prime time {sum(nonmemqueries_prime_time) / reps} avg. per query {sum(nonmemqueries_prime_time) / (reps * nonmemqueries)}")
    print(
        f"Avg nonmem. proof time {sum(nonmemqueries_proof_time) / reps} avg. per query {sum(nonmemqueries_proof_time) / (reps * nonmemqueries)}")
    print(
        f"Avg nonmem. verify time {sum(nonmemqueries_verify_time) / reps} avg. per query {sum(nonmemqueries_verify_time) / (reps * nonmemqueries)}")
    memqueries = sum(memqueries_prime_time) / reps, sum(memqueries_proof_time) / reps, sum(
        memqueries_verify_time) / reps
    nonmemqueries = sum(nonmemqueries_prime_time) / reps, sum(nonmemqueries_proof_time) / reps, sum(
        nonmemqueries_verify_time) / reps
    insertion_time = sum(insertion_times) / reps
    safe_prime_time = sum(safe_prime_times) / reps
    prime_time = sum(prime_times) / reps
    memwit_size = sum(memwitness_size) / len(memwitness_size)
    nonmemwit_size = sum(nonmemwitness_size) / len(nonmemwitness_size)
    return memqueries, nonmemqueries, insertion_time, safe_prime_time, prime_time, memwit_size, nonmemwit_size


# MerkleTreeBenchmark(100000, 10000, 10000, 5)
# RSABenchmark(10000, 800, 800, 5, security=128)

def run_rsa_benchmarks():
    insertions = [2 ** j for j in range(4, 14)]
    query_percent = [0.1, 0.2, 0.5]
    reps = 5
    security = 2048
    f = open("benchmarks.txt", "a")
    f.write("--START RSA BENCHMARK--\n")
    rsa_modulus = generate_safe_RSA_modulus(security)
    for n in insertions:
        for j in query_percent:
            queries = int(n * j)
            print(f"Starting run with {n} insertions, {queries} queries and hash function ?")
            hash_security = 40
            # prime_hash = PrimeHashv2(hash_security)
            prime_hash = PrimeHash(hash_security)
            memqueries, nonmemqueries, insertion_time, safe_prime_time, prime_time, memwit_size, nonmem_size = RSABenchmark(
                n, queries, queries,
                reps, prime_hash, rsa_modulus,
                security=security,)
            text = f"{memqueries}, {nonmemqueries}, {insertion_time}, {safe_prime_time}, {prime_time}, {security}\n"
            print(text)
            f.write(text)
    f.write("--END RSA BENCHMARK--\n")
    f.close()


run_rsa_benchmarks()
