import copy
import random
import time

from gmpy2 import powmod, gcdext

from MerkleTree import MerkleTree
from RSAAccumulator import Accumulator, generate_safe_RSA_modulus, verify_membership, verify_nonmembership, \
    verify_bulk_nonmembership, AccumulatorNoU
from prime_hash import RandomOraclePrimeHash, PrimeHash
from TestObject import TestObject
from Verification import verify
import matplotlib.pyplot as plt


# Sorry if you are reading this...
# This code has not been cleaned

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


# This really should use the measurement class
# but I am way too lazy
# As we will not be evaluated on the code --- this is ugly and we didnt bother refactoring it
def RSABenchmark(iters, memqueries, nonmemqueries, reps, prime_hash, acc_og, phin):
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
    bulk_sizes = [100, iters]
    bulks_lens = len(bulk_sizes)
    bulk_membership_gen = [[] for _ in range(bulks_lens)]
    bulk_membership_ver = [[] for _ in range(bulks_lens)]
    bulk_nonmembership_gen = [[] for _ in range(bulks_lens)]
    bulk_nonmembership_ver = [[] for _ in range(bulks_lens)]
    for j in range(reps):
        acc = copy.deepcopy(acc_og)
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
        start_time = time.time()
        mem_witnesses = []
        mem_primes = prime_objects
        end_time = time.time()
        memqueries_prime_time.append(end_time - start_time)
        start_time = time.time()
        for i in range(memqueries):
            xprime = mem_primes[i]
            witness = acc.get_membership(xprime)
            mem_witnesses.append(witness)
            memwitness_size.append(len(bin(witness)))
        end_time = time.time()
        memqueries_proof_time.append(end_time - start_time)
        start_time = time.time()
        for i in range(memqueries + verify_extra):
            xprime = mem_primes[i % memqueries]
            witness = mem_witnesses[i % memqueries]
            assert verify_membership(xprime, witness, acc.acc, acc.n)
        end_time = time.time()
        memqueries_verify_time.append(end_time - start_time)

        for idx in range(bulks_lens):
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

        for idx in range(bulks_lens):
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
        start_time = time.time()
        for i in range(nonmemqueries + verify_extra):
            xprime = prime_hashes[i % nonmemqueries]
            a, d = nonmem_witnesses[i % nonmemqueries]
            assert verify_nonmembership(d, a, xprime, acc.acc, acc.n, acc.g)
        end_time = time.time()
        nonmemqueries_verify_time.append(end_time - start_time)
        start_time = time.time()
        for i in range(iters):
            ele = prime_objects[i]
            _, a, b = gcdext(ele, phin)
            # a*ele + b * phin = 1 so we delete
            new_acc = powmod(acc.acc, ele, acc.n)
            acc.remove(ele, new_acc)
        end_time = time.time()
        deletion_times.append(end_time - start_time)
        hash_queries = len(prime_hash.prime_map)
    memqueries = sum(memqueries_prime_time) / reps, sum(memqueries_proof_time) / reps, sum(
        memqueries_verify_time) /  (reps)
    nonmemqueries = sum(nonmemqueries_prime_time) / reps, sum(nonmemqueries_proof_time) / reps, sum(
        nonmemqueries_verify_time) /  (reps)
    insertion_time = sum(insertion_times) / reps
    deletion_time = sum(deletion_times) / reps
    safe_prime_time = sum(safe_prime_times) / reps
    prime_time = sum(prime_times) / reps
    memwit_size = sum(memwitness_size) / len(memwitness_size)
    nonmemwit_size = sum(nonmemwitness_size) / len(nonmemwitness_size)
    avg_hash_size = sum(prime_hash.prime_map.values()) / hash_queries
    return memqueries, nonmemqueries, insertion_time, safe_prime_time, prime_time, memwit_size, nonmemwit_size, bulk_membership_gen, bulk_membership_ver, bulk_nonmembership_gen, bulk_nonmembership_ver, avg_hash_size, deletion_time


def run_rsa_benchmarks(prime_hash, label, acc, phin):
    insertions = [10000 * j for j in range(1, 11)]
    queries = [1]
    reps = 5
    security = 2048
    f = open("benchmarks.txt", "a")
    f.write("--START RSA BENCHMARK--\n")
    for n in insertions:
        for j in queries:
            query_amount = j
            print(f"Starting run with {n} insertions, {query_amount} queries and hash function ?")
            # prime_hash = PrimeHash(hash_security)
            # THIS IS SO DISGUSTING I AM SORRY
            acc_copy = copy.deepcopy(acc)
            memqueries_time, nonmemqueries_time, insertion_time, safe_prime_time, prime_time, memwit_size, nonmem_size, bulk_membership_gen, bulk_membership_ver, bulk_nonmembership_gen, bulk_nonmembership_ver, avg_hash_size, deletion_time = RSABenchmark(
                n, query_amount, query_amount,
                reps, prime_hash, acc_copy, phin)
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
    return read_bulk_benchmarks(get_measurements(measurements), idx)

def read_bulk_benchmarks(measurements : 'Measurements', idx):

    filename = "bulk_membership.txt"
    fil = open(filename, 'r')
    text = fil.read()
    lines = text.split("\n")
    proof1 = []
    proof2 = []
    ver1 = []
    ver2 = []
    line = lines[idx]
    line = line.split("; |")
    proof = line[0]
    #print(line[0])
    ver = line[1].split("ø")[0]
    for pair in proof.split("; ["):
        pair = pair.replace(']', '')
        pair = pair.replace('[', '')
        #print(pair)
        nums = pair.split(",")
        proof1.append(float(nums[0]))
        proof2.append(float(nums[1]))
        ver = line[1]
    for pair in ver.split("; ")[:-1]:
        pair = pair.replace(']', '')
        pair = pair.replace('[', '')
        nums = pair.split(",")
        ver1.append(float(nums[0]))
        ver2.append(float(nums[1]))
    measurements.bulk_measurements[0] = proof1
    measurements.bulk_measurements[1] = proof2
    measurements.bulk_measurements[3] = ver1
    measurements.bulk_measurements[4] = ver2
    return measurements


class Measurements():

    def __init__(self, insertion_times, k, memqueries_proof_times, memqueries_verify_times, nonmemqueries_proof_times,
                 nonmemqueries_verify_times, nonmemwit_size, ns, sec):
        self.sec = sec
        self.insertions = ns
        self.nonmemwit_size = nonmemwit_size
        self.nonmemqueries_verify_times = nonmemqueries_verify_times
        self.nonmemqueries_proof_times = nonmemqueries_proof_times
        self.memqueries_verify_times = memqueries_verify_times
        self.memqueries_proof_times = memqueries_proof_times
        self.avg_hash_size = k
        self.insertion_times = insertion_times
        self.bulk_measurements = []
        self.deletion_times = []

    def get_all(self):
        return self.insertion_times, self.avg_hash_size, self.memqueries_proof_times, self.memqueries_verify_times, self.nonmemqueries_proof_times, self.nonmemqueries_verify_times, self.nonmemwit_size, self.insertions, self.sec



def get_measurements(measurements):
    ns = []
    memqueries_proof_times = []
    memqueries_verify_times = []
    nonmemqueries_proof_times = []
    nonmemqueries_verify_times = []
    insertion_times = []
    memwit_size = []
    nonmemwit_size = []
    bulk_measurements = [[] for _ in range(16)]
    deletion_times = []
    verify_extra = 100
    reps = 5
    for measurement_no_split in measurements.split("\n")[:-1]:
        measurement = measurement_no_split.split(",")
        ns.append(int(measurement[0]))
        queries = int(measurement[1])
        k = float(measurement[11])
        sec = int(measurement[10])
        memqueries_proof_times.append(float(measurement[3]) / queries)
        memqueries_verify_times.append(float(measurement[4]) / int(measurement[1]) * reps / (reps * (1+verify_extra)))
        nonmemqueries_proof_times.append(float(measurement[6]) / int(measurement[1]))
        nonmemqueries_verify_times.append(float(measurement[7]) / int(measurement[1])* reps / (reps * (1+verify_extra)))
        insertion_times.append(float(measurement[8]))
        memwit_size.append(float(measurement[12]))
        nonmemwit_size.append(float(measurement[13]))
        deletion_times.append(float(measurement[55]))
        measurement2 = measurement_no_split.split("[")
        bulk_times = []
        for arrays in measurement2[1:]:
            arrays = arrays.split("]")[0]
            narray = [float(x) for x in arrays.split(',')[:-1]]
            bulk_times.append(sum(narray) / len(narray))
        for i in range(len(bulk_times)):
            bulk_measurements[i].append(bulk_times[i])

    measurementObject = Measurements(insertion_times, k, memqueries_proof_times, memqueries_verify_times, nonmemqueries_proof_times,
                        nonmemqueries_verify_times, nonmemwit_size, ns, sec)
    measurementObject.bulk_measurements = bulk_measurements
    measurementObject.deletion_times = deletion_times
    return measurementObject
    #print(bulk_measurements[0][-1])
    #print(bulk_measurements[3][-1])


def make_plots():
    # We want to plot hash size 40, 80
    # Bulk queries for 10, 100, 1000 and n
    benchmark_results = "benchmark_results/"
    measurement40 = read_benchmarks(1)
    measurement80 = read_benchmarks(2)
    measurement402 = read_benchmarks(3)
    measurement802 = read_benchmarks(4)
    # So plots we want
    # 4 inserts
    ns = measurement402.insertions


    def update_insert_times(times):
        interval = 10000
        new_times = []
        for i in range(0, len(times)):
            if i > 1:
                new_times.append((times[i] - times[i - 1])/(interval))
            else:
                new_times.append((times[i]/(interval)))
        return new_times
    uns = ns

    plt.title("Avg. insertion time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    # avg for 0-10k 10-20k and so on.
    plt.plot(uns, update_insert_times(measurement40.insertion_times), label="hash40")
    plt.plot(uns, update_insert_times(measurement80.insertion_times), label="hash80")
    plt.plot(uns, update_insert_times(measurement402.insertion_times), '--',label="No-u-hash40")
    plt.plot(uns, update_insert_times(measurement802.insertion_times), '--',label="No-u-hash80")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "insertion_times.png")
    plt.show()

    # 4 deletions
    plt.title("Avg. deletion time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(uns, update_insert_times(measurement40.deletion_times), label="hash40")
    plt.plot(uns, update_insert_times(measurement80.deletion_times), label="hash80")
    plt.plot(uns, update_insert_times(measurement402.deletion_times), '--',label="No-u-hash40")
    plt.plot(uns, update_insert_times(measurement802.deletion_times), '--',label="No-u-hash80")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "deletion_times.png")
    plt.show()

    # 4 membership gen
    plt.title("Avg. membership proof generation time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ns, measurement40.memqueries_proof_times, label="hash40")
    plt.plot(ns, measurement80.memqueries_proof_times, label="hash80")
    plt.plot(ns, measurement402.memqueries_proof_times, '--', label="No-u-hash40")
    plt.plot(ns, measurement802.memqueries_proof_times,'--', label="No-u-hash80")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "membership_proof.png")
    plt.show()

    # 2 memship veri

    plt.title("Avg. membership verification time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ns, measurement40.memqueries_verify_times, label="hash40")
    plt.plot(ns, measurement80.memqueries_verify_times, label="hash80")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "membership_verify.png")
    plt.show()
    # 4 nonmembership gen
    plt.title("Avg. non-membership proof generation time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ns, measurement40.nonmemqueries_proof_times, label="hash40")
    plt.plot(ns, measurement80.nonmemqueries_proof_times, label="hash80")
    plt.plot(ns, measurement402.nonmemqueries_proof_times, '--', label="No-u-hash40")
    plt.plot(ns, measurement802.nonmemqueries_proof_times, '--', label="No-u-hash80")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "nonmembership_proof.png")
    plt.show()

    # 2 nomemgen
    plt.title("Avg. non-membership verification time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ns, measurement40.nonmemqueries_verify_times, label="hash40")
    plt.plot(ns, measurement80.nonmemqueries_verify_times, label="hash80")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "nonmembership_verify.png")
    plt.show()

    # 4 bulk memship gen
    #bulk_sizes = [100, 1000, 5000, iters]
    plt.title("Total bulk membership proof generation time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    print(len(ns))
    print(len(measurement80.bulk_measurements[0]))
    plt.plot(ns, measurement80.bulk_measurements[0], label="hash80-100")
    plt.plot(ns, measurement80.bulk_measurements[1], label="hash80-all") # change 3 to 1
    plt.plot(ns, measurement802.bulk_measurements[0],'--', label="No-u-hash80-100")
    plt.plot(ns, measurement802.bulk_measurements[1], '--', label="No-u-hash80-all")
    plt.plot(ns, measurement40.bulk_measurements[1], label="hash40-all")
    plt.plot(ns, measurement402.bulk_measurements[1], '--',label="No-u-hash40-all")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "bulk_membership_proof.png")
    plt.show()

    plt.title("Avg. bulk membership proof generation time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))

    def get_avg(measure):
        return [measure[i]/ns[i] for i in range(len(ns))]

    def get_avg100(measure):
        return [m/100 for m in measure]

    #plt.plot(ns, [m/100 for m in measurement80.bulk_measurements[0]], label="hash80-100")
    plt.plot(ns, get_avg(measurement80.bulk_measurements[1]), label="hash80-all")
    #plt.plot(ns, [m/100 for m in measurement802.bulk_measurements[0]],'--', label="No-u-hash80-100")
    plt.plot(ns, get_avg(measurement802.bulk_measurements[1]), '--', label="No-u-hash80-all")
    plt.plot(ns, get_avg(measurement40.bulk_measurements[1]), label="hash40-all")
    plt.plot(ns, get_avg(measurement402.bulk_measurements[1]), '--',label="No-u-hash40-all")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "bulk_membership_proof_avg.png")
    plt.show()

    plt.title("Total bulk membership verification time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.plot(ns, measurement80.bulk_measurements[2], label="hash80-100")
    plt.plot(ns, measurement80.bulk_measurements[3], label="hash80-all")
    plt.plot(ns, measurement40.bulk_measurements[2], label="hash40-100")
    plt.plot(ns, measurement40.bulk_measurements[3], label="hash40-all")
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig(benchmark_results + "bulk_membership_verify.png")

    # 4 bulk nonmembership gen
    plt.title("Avg. bulk non-membership proof generation time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    #plt.plot(ns, get_avg100(measurement80.bulk_measurements[8]), label="hash80-100")
    plt.plot(ns, get_avg(measurement80.bulk_measurements[4 + 1]), label="hash80-all")
    #plt.plot(ns, get_avg100(measurement802.bulk_measurements[8]), '--', label="No-u-hash80-100")
    plt.plot(ns, get_avg(measurement802.bulk_measurements[4+1]), '--', label="No-u-hash80-all")
    plt.plot(ns, get_avg(measurement40.bulk_measurements[4+1]), label="hash40-all")
    plt.plot(ns, get_avg(measurement402.bulk_measurements[4+1]), '--',label="No-u-hash40-all")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "bulk_nonmembership_proof_avg.png")
    plt.show()

    plt.title("Total bulk non-membership proof generation time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ns, measurement80.bulk_measurements[4], label="hash80-100")
    plt.plot(ns, measurement80.bulk_measurements[4+1], label="hash80-all")
    plt.plot(ns, measurement802.bulk_measurements[4], '--', label="No-u-hash80-100")
    plt.plot(ns, measurement802.bulk_measurements[4+1], '--', label="No-u-hash80-all")
    plt.plot(ns, measurement40.bulk_measurements[4+1], label="hash40-all")
    plt.plot(ns, measurement402.bulk_measurements[4+1], '--',label="No-u-hash40-all")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "bulk_nonmembership_proof.png")
    plt.show()

    # 2 bulk nonmembership verify
    plt.title("Total bulk non-membership verify time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ns, measurement80.bulk_measurements[6], label="hash80-100")
    plt.plot(ns, measurement80.bulk_measurements[6 + 1], label="hash80-all")
    plt.plot(ns, measurement40.bulk_measurements[6], label="hash40-100")
    plt.plot(ns, measurement40.bulk_measurements[6+1], label="hash40-all")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "bulk_nonmembership_verify.png")
    plt.show()

    plt.title("Avg. bulk non-membership verify time")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ns, get_avg100(measurement80.bulk_measurements[6]), label="hash80-100")
    plt.plot(ns, get_avg(measurement80.bulk_measurements[6+1]), label="hash80-all")
    plt.plot(ns, get_avg100(measurement40.bulk_measurements[6]), label="hash40-100")
    plt.plot(ns, get_avg(measurement40.bulk_measurements[6+1]), label="hash40-all")
    plt.legend(loc="upper left")
    plt.savefig(benchmark_results + "bulk_nonmembership_verify_avg.png")
    plt.show()

    assert measurement40.insertions == measurement80.insertions == measurement402.insertions == measurement802.insertions


def run():
    print("Generating safe RSA modulus")
    rsa_modulus, p, q = generate_safe_RSA_modulus(2048)
    print("Generation done")
    phin = (p-1)*(q-1)
    acc1 = Accumulator(2048, rsa_modulus)
    acc2 = AccumulatorNoU(2048, rsa_modulus)
    hash40 = RandomOraclePrimeHash(40)
    hash80 = RandomOraclePrimeHash(80)
    hash256 = RandomOraclePrimeHash(256)
    #run_rsa_benchmarks(hash40, "hash40acc1", acc1, phin)
    #run_rsa_benchmarks(hash40, "hash40acc2", acc2, phin)
    run_rsa_benchmarks(hash256, "hash256acc1", acc1, phin)
    run_rsa_benchmarks(hash256, "hash256acc2", acc2, phin)
    #run_rsa_benchmarks(hash80, "hash80acc1", acc1, phin)
    #run_rsa_benchmarks(hash80, "hash80acc2", acc2, phin)

run()
#read_benchmarks(1)
#make_plots()