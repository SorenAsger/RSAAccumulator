import random
import time

from gmpy2 import powmod, gcdext

from MerkleTree import MerkleTree
from RSAAccumulator import Accumulator, generate_safe_RSA_modulus, verify_membership, verify_nonmembership, \
    verify_bulk_nonmembership, AccumulatorNoU
from prime_hash import PrimeHashv2, PrimeHash
from TestObject import TestObject
from Verification import verify
import matplotlib.pyplot as plt


# Sorry if you are reading this...

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


# There really should be a class for all these measurements that should be used...
# but I am way too lazy
def RSABenchmark(iters, memqueries, nonmemqueries, reps, prime_hash, acc, phin, security=2048):
    prime_times = []
    insertion_times = []
    deletion_times = []
    memqueries_prime_time = []
    memqueries_proof_time = []
    memqueries_verify_time = []
    memwitness_size = []
    nonmemqueries_proof_time = []
    nonmemqueries_verify_time = []
    nonmemqueries_prime_time = []
    safe_prime_times = []
    nonmemwitness_size = []
    verify_extra = 100
    bulk_sizes = [100, 1000, 5000, iters]
    bulk_membership_gen = [[] for _ in range(4)]  # 100, 1000, 10000? n
    bulk_membership_ver = [[] for _ in range(4)]  # 100, 1000, 10000? n
    bulk_nonmembership_gen = [[] for _ in range(4)]  # 100, 1000, 10000? n
    bulk_nonmembership_ver = [[] for _ in range(4)]  # 100, 1000, 10000? n
    for j in range(reps):
        start_time = time.time()
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
        for i in range(memqueries + verify_extra):
            xprime = mem_primes[i % memqueries]
            witness = mem_witnesses[i % memqueries]
            assert verify_membership(xprime, witness, acc.acc, acc.n)
        end_time = time.time()
        memqueries_verify_time.append(end_time - start_time)
        print(f"Memquery {memqueries} verify time {end_time - start_time}")

        for idx in range(len(bulk_nonmembership_gen)):
            start_time = time.time()
            witnesses = acc.get_bulk_membership(mem_primes[:bulk_sizes[idx]])
            end_time = time.time()
            bulk_membership_gen[idx].append(end_time - start_time)
            start_time = time.time()
            for x, w in witnesses:
                assert verify_membership(x, w, acc.acc, acc.n)
            end_time = time.time()
            bulk_membership_ver[idx].append(end_time - start_time)
        nonmem_primes = []
        for i in range(iters):
            nonmem_primes.append(prime_hash.prime_hash(i * 2 + 1))

        for idx in range(len(bulk_nonmembership_gen)):
            start_time = time.time()
            a, d, v = acc.get_bulk_nonmembership(nonmem_primes[:bulk_sizes[idx]])
            end_time = time.time()
            bulk_nonmembership_gen[idx].append(end_time - start_time)
            start_time = time.time()
            verify_bulk_nonmembership(d, a, nonmem_primes[:bulk_sizes[idx]], acc.acc, acc.n, acc.g, v)
            end_time = time.time()
            bulk_nonmembership_ver[idx].append(end_time - start_time)

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
        for i in range(nonmemqueries + verify_extra):
            xprime = prime_hashes[i % nonmemqueries]
            a, d = nonmem_witnesses[i % nonmemqueries]
            assert verify_nonmembership(d, a, xprime, acc.acc, acc.n, acc.g)
        end_time = time.time()
        print(f"Nonmemquery verify time {end_time - start_time}")
        nonmemqueries_verify_time.append(end_time - start_time)

        start_time = time.time()
        for i in range(iters):
            ele = prime_objects[i]
            _, a, b = gcdext(ele, phin)
            # a*ele + b * phin = 1
            new_acc = powmod(acc.acc, ele, acc.n)
            acc.remove(ele, new_acc)
        end_time = time.time()
        deletion_times.append(end_time - start_time)
        hash_queries = len(prime_hash.prime_map)
        print("hash queries")
        print("avg hash size", sum(prime_hash.prime_map.values()) / hash_queries)
        print(hash_queries)
        print(iters + nonmemqueries)
        # assert hash_queries == (iters + nonmemqueries)
        # print(f"Nonmemqueries {nonmemqueries} time {end_time-start_time}")
    print(f"Avg prime_times time {sum(prime_times) / reps} avg. per query {sum(prime_times) / (reps * iters)}")
    print(f"Avg safe_prime_times time {sum(safe_prime_times) / reps}")
    print(f"Avg ins. time {sum(insertion_times) / reps} and avg. per query {sum(insertion_times) / (reps * iters)}")
    print(
        f"Avg mem. prime time {sum(memqueries_prime_time) / reps} avg. per query {sum(memqueries_prime_time) / (reps * memqueries)}")
    print(
        f"Avg mem. proof time {sum(memqueries_proof_time) / reps} avg. per query {sum(memqueries_proof_time) / (reps * memqueries)}")
    print(
        f"Avg mem. verify time {sum(memqueries_verify_time) / reps} avg. per query {sum(memqueries_verify_time) / (reps * (memqueries + verify_extra))}")
    print(
        f"Avg nonmem. prime time {sum(nonmemqueries_prime_time) / reps} avg. per query {sum(nonmemqueries_prime_time) / (reps * nonmemqueries)}")
    print(
        f"Avg nonmem. proof time {sum(nonmemqueries_proof_time) / reps} avg. per query {sum(nonmemqueries_proof_time) / (reps * nonmemqueries)}")
    print(
        f"Avg nonmem. verify time {sum(nonmemqueries_verify_time) / reps} avg. per query {sum(nonmemqueries_verify_time) / (reps * (nonmemqueries + verify_extra))}")
    memqueries = sum(memqueries_prime_time) / reps, sum(memqueries_proof_time) / reps, sum(
        memqueries_verify_time) / reps
    nonmemqueries = sum(nonmemqueries_prime_time) / reps, sum(nonmemqueries_proof_time) / reps, sum(
        nonmemqueries_verify_time) / reps
    insertion_time = sum(insertion_times) / reps
    deletion_time = sum(deletion_times) / reps
    safe_prime_time = sum(safe_prime_times) / reps
    prime_time = sum(prime_times) / reps
    memwit_size = sum(memwitness_size) / len(memwitness_size)
    nonmemwit_size = sum(nonmemwitness_size) / len(nonmemwitness_size)
    avg_hash_size = sum(prime_hash.prime_map.values()) / hash_queries
    return memqueries, nonmemqueries, insertion_time, safe_prime_time, prime_time, memwit_size, nonmemwit_size, bulk_membership_gen, bulk_membership_ver, bulk_nonmembership_gen, bulk_nonmembership_ver, avg_hash_size, deletion_time


# MerkleTreeBenchmark(100000, 10000, 10000, 5)
# RSABenchmark(10000, 800, 800, 5, security=128)

def run_rsa_benchmarks(prime_hash, label, acc, phin):
    insertions = [5000 * j for j in range(1, 20)]
    queries = [1]
    reps = 4
    security = 2048
    f = open("benchmarks.txt", "a")
    f.write("--START RSA BENCHMARK--\n")
    for n in insertions:
        for j in queries:
            query_amount = j
            print(f"Starting run with {n} insertions, {query_amount} queries and hash function ?")
            # prime_hash = PrimeHash(hash_security)
            # THIS IS SO DISGUSTING I AM SORRY
            memqueries_time, nonmemqueries_time, insertion_time, safe_prime_time, prime_time, memwit_size, nonmem_size, bulk_membership_gen, bulk_membership_ver, bulk_nonmembership_gen, bulk_nonmembership_ver, avg_hash_size, deletion_time = RSABenchmark(
                n, query_amount, query_amount,
                reps, prime_hash, acc, phin,
                security=security)
            tkst = ""
            for time in bulk_membership_gen:
                tkst += str(time) + ", "
            for time in bulk_membership_ver:
                tkst += str(time) + ", "
            for time in bulk_nonmembership_gen:
                tkst += str(time) + ", "
            for time in bulk_nonmembership_ver:
                tkst += str(time) + ", "
            text = f"{n}, {query_amount}, {memqueries_time}, {nonmemqueries_time}, {insertion_time}, {prime_time}, {security}, {avg_hash_size}, " \
                   f"{memwit_size}, {nonmem_size}, {tkst}, {deletion_time}, {label}\n"
            print(text)
            f.write(text)
    f.close()


def read_benchmarks(idx):
    f = open("benchmarks.txt", "r")
    text = f.read().split("--START RSA BENCHMARK--\n")
    measurements = text[idx].replace("(", "").replace(")", "")
    f.close()
    return get_measurements(measurements)


class Measurements():

    def __init__(self, insertion_times, k, memqueries_proof_times, memqueries_verify_times, nonmemqueries_proof_times,
                 nonmemqueries_verify_times, nonmemwit_size, ns, sec, avg_hash_size):
        self.sec = sec
        self.insertions = ns
        self.nonmemwit_size = nonmemwit_size
        self.nonmemqueries_verify_times = nonmemqueries_verify_times
        self.nonmemqueries_proof_times = nonmemqueries_proof_times
        self.memqueries_verify_times = memqueries_verify_times
        self.memqueries_proof_times = memqueries_proof_times
        self.avg_hash_size = k
        self.insertion_times = insertion_times

    def get_all(self):
        return self.insertion_times, self.avg_hash_size, self.memqueries_proof_times, self.memqueries_verify_times, self.nonmemqueries_proof_times, self.nonmemqueries_verify_times, self.nonmemwit_size, self.insertions, self.sec


def read_file(idx1=1, idx2=2):
    f = open("benchmarks.txt", "r")
    text = f.read().split("--START RSA BENCHMARK--\n")
    measurements = text[idx1].replace("(", "").replace(")", "")
    measurements2 = text[idx2].replace("(", "").replace(")", "")
    insertion_times, k1, memqueries_proof_times, memqueries_verify_times, nonmemqueries_proof_times, nonmemqueries_verify_times, nonmemwit_size, ns, sec = get_measurements(
        measurements).get_all()
    insertion_times2, k2, memqueries_proof_times2, memqueries_verify_times2, nonmemqueries_proof_times2, nonmemqueries_verify_times2, nonmemwit_size2, ns2, sec2 = get_measurements(
        measurements2).get_all()
    assert ns == ns2
    print(f"RSA security {sec}")
    plt.title(f"Avg. membership witness generation time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    label_1 = "Hash size 60"
    label_2 = "Hash size 35"
    plt.plot(ns, memqueries_proof_times, label=label_1)
    plt.plot(ns, memqueries_proof_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("memshipwgen.png")

    plt.title(f"Avg. membership witness verification time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.plot(ns, memqueries_verify_times, label=label_1)
    plt.plot(ns, memqueries_verify_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("memshipveri.png")

    plt.title(f"Insertion time")
    plt.xlabel(f"Total insertions")
    plt.ylabel(f"Total time in seconds")
    plt.plot(ns, insertion_times, label=label_1)
    plt.plot(ns, insertion_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("insertion_time.png")

    plt.title(f"Avg. non-membership witness generation time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.plot(ns, nonmemqueries_proof_times, label=label_1)
    plt.plot(ns, nonmemqueries_proof_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("nonmemshipgen.png")

    plt.title(f"Avg. non-membership witness verification time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.plot(ns, nonmemqueries_verify_times, label=label_1)
    plt.plot(ns, nonmemqueries_verify_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("nonmemveri.png")

    plt.title(f"Non-membership witness size with hash size: {k1}")
    plt.plot(ns, nonmemwit_size, label=label_1)
    plt.plot(ns, nonmemwit_size2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()


def get_measurements(measurements):
    ns = []
    memqueries_proof_times = []
    memqueries_verify_times = []
    nonmemqueries_proof_times = []
    nonmemqueries_verify_times = []
    insertion_times = []
    memwit_size = []
    nonmemwit_size = []
    for measurement in measurements.split("\n")[:-1]:
        measurement = measurement.split(",")
        ns.append(int(measurement[0]))
        queries = int(measurement[1])
        k = int(measurement[11])
        sec = int(measurement[10])
        memqueries_proof_times.append(float(measurement[3]) / queries)
        memqueries_verify_times.append(float(measurement[4]) / int(measurement[1]))
        nonmemqueries_proof_times.append(float(measurement[6]) / int(measurement[1]))
        nonmemqueries_verify_times.append(float(measurement[7]) / int(measurement[1]))
        insertion_times.append(float(measurement[8]))
        memwit_size.append(float(measurement[12]))
        nonmemwit_size.append(float(measurement[13]))
    return Measurements(insertion_times, k, memqueries_proof_times, memqueries_verify_times, nonmemqueries_proof_times,
                        nonmemqueries_verify_times, nonmemwit_size, ns, sec)


def make_plots():
    # We want to plot hash size 40, 80
    # Bulk queries for 10, 100, 1000 and n
    pass
    measurement40 = read_benchmarks(1)
    measurement80 = read_benchmarks(2)
    assert measurement40.insertions == measurement80.insertions


rsa_modulus, p, q = generate_safe_RSA_modulus(2048)
phin = (p-1)*(q-1)
acc1 = Accumulator(2048, rsa_modulus)
acc2 = AccumulatorNoU(2048, rsa_modulus)
hash40 = PrimeHashv2(40)
hash80 = PrimeHashv2(80)
run_rsa_benchmarks(hash40, "hash40acc1", acc1, phin)
run_rsa_benchmarks(hash80, "hash80acc1", acc1, phin)
run_rsa_benchmarks(hash40, "hash40acc2", acc2, phin)
run_rsa_benchmarks(hash80, "hash80acc2", acc2, phin)
