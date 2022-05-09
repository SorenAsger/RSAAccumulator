import time
import matplotlib.pyplot as plt
from RSAAccumulator import Accumulator, verify_membership, verify_bulk_nonmembership, generate_safe_RSA_modulus
from prime_hash import PrimeHashv2, PrimeHash


def RSABenchmark_bulk(iters, memqueries, nonmemqueries, reps, prime_hash, rsa_modulus, security=2048):
    prime_times = []
    insertion_times = []
    memqueries_prime_time = []
    memqueries_proof_time = []
    memqueries_verify_time = []
    memwitness_size = []
    nonmemqueries_proof_time = []
    nonmemqueries_verify_time = []
    nonmemqueries_prime_time = []
    nonmemwitness_size = []
    for j in range(reps):
        acc = Accumulator(security, rsa_modulus)
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
        mem_primes = []
        for i in range(memqueries):
            mem_primes.append(prime_hash.prime_hash(i * 2))
        end_time = time.time()
        memqueries_prime_time.append(end_time - start_time)
        print(f"Memquery {memqueries} prime time {end_time - start_time}")
        start_time = time.time()
        witnesses = acc.get_bulk_membership(mem_primes)
        end_time = time.time()
        memwitness_size.append(sum([len(bin(w[1])) for w in witnesses]))
        print(f"Memquery {memqueries} proof time {end_time - start_time}")
        memqueries_proof_time.append(end_time - start_time)
        start_time = time.time()
        for x, w in witnesses:
            assert verify_membership(x, w, acc.acc, acc.n)
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
        a, d, v = acc.get_bulk_nonmembership(prime_hashes)
        nonmemwitness_size.append(len(bin(a)) + len(bin(d)) + len(bin(v)))
        end_time = time.time()
        nonmemqueries_proof_time.append(end_time - start_time)
        print(f"Nonmemquery proof time {end_time - start_time}")
        start_time = time.time()
        assert verify_bulk_nonmembership(d, a, prime_hashes, acc.acc, acc.n, acc.g, v)
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
    prime_time = sum(prime_times) / reps
    memwit_size = sum(memwitness_size) / len(memwitness_size)
    nonmemwit_size = sum(nonmemwitness_size) / len(nonmemwitness_size)
    return memqueries, nonmemqueries, insertion_time, prime_time, memwit_size, nonmemwit_size


def run_rsa_benchmarks_bulk(hash_security=60):
    insertions = [5000 * j for j in range(1, 10)]
    queries = [2 ^ 9]
    reps = 5
    security = 1024
    f = open("benchmarksbulk.txt", "a")
    f.write("--START RSA BENCHMARK--\n")
    rsa_modulus = generate_safe_RSA_modulus(security)
    for n in insertions:
        for j in queries:
            query_amount = n
            print(f"Starting run with {n} insertions, {query_amount} queries and hash function ?")
            prime_hash = PrimeHashv2(hash_security)
            # prime_hash = PrimeHash(hash_security)
            memqueries_time, nonmemqueries_time, insertion_time, prime_time, memwit_size, nonmem_size = RSABenchmark_bulk(
                n, query_amount, query_amount,
                reps, prime_hash, rsa_modulus,
                security=security, )
            text = f"{n}, {query_amount}, {memqueries_time}, {nonmemqueries_time}, {insertion_time}, {prime_time}, {security}, {hash_security}, " \
                   f"{memwit_size}, {nonmem_size},\n"
            print(text)
            f.write(text)
    f.close()


def read_filesingle(idx1=1):
    f = open("benchmarksbulk.txt", "r")
    text = f.read().split("--START RSA BENCHMARK--\n")
    measurements = text[idx1].replace("(", "").replace(")", "")
    # measurements2 = text[idx2].replace("(", "").replace(")", "")
    insertion_times, k1, memqueries_proof_times, memqueries_verify_times, nonmemqueries_proof_times, nonmemqueries_verify_times, nonmemwit_size, ns, sec = get_measurements(
        measurements).get_all()
    # insertion_times2, k2, memqueries_proof_times2, memqueries_verify_times2, nonmemqueries_proof_times2, nonmemqueries_verify_times2, nonmemwit_size2, ns2, sec2 = get_measurements(
    #    measurements2)
    # assert ns == ns2
    print(f"RSA security {sec}")
    plt.title(f"Avg. membership witness generation time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    label_1 = "Hash size 60"
    # label_2 = "Hash size 35"
    plt.plot(ns, memqueries_proof_times, label=label_1)
    # plt.plot(ns, memqueries_proof_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("bulk_memgen.png")

    plt.title(f"Avg. membership witness verification time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.plot(ns, memqueries_verify_times, label=label_1)
    # plt.plot(ns, memqueries_verify_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("bulk_memverify.png")

    plt.title(f"Insertion time")
    plt.xlabel(f"Total insertions")
    plt.ylabel(f"Total time in seconds")
    plt.plot(ns, insertion_times, label=label_1)
    # plt.plot(ns, insertion_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("insertion_time.png")

    plt.title(f"Avg. non-membership witness generation time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.plot(ns, nonmemqueries_proof_times, label=label_1)
    # plt.plot(ns, nonmemqueries_proof_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("bulk_nonmemgen.png")

    plt.title(f"Avg. non-membership witness verification time with hash size: {k1}")
    plt.xlabel("Total insertions")
    plt.ylabel("Time in seconds")
    plt.plot(ns, nonmemqueries_verify_times, label=label_1)
    # plt.plot(ns, nonmemqueries_verify_times2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()
    plt.savefig("bulk_nonmemver.png")

    plt.title(f"Non-membership witness size with hash size: {k1}")
    plt.plot(ns, nonmemwit_size, label=label_1)
    # plt.plot(ns, nonmemwit_size2, label=label_2)
    plt.legend(loc="upper left")
    plt.show()


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
        print("Queries!:", queries)
        sec = int(measurement[10])
        memqueries_proof_times.append(float(measurement[3]) / queries)
        memqueries_verify_times.append(float(measurement[4]) / queries)
        nonmemqueries_proof_times.append(float(measurement[6]) / queries)
        print(float(measurement[6]))
        print(float(measurement[6]) / queries)
        nonmemqueries_verify_times.append(float(measurement[7]) / queries)
        print(float(measurement[7]))
        print(float(measurement[7]) / queries)
        insertion_times.append(float(measurement[8]) / queries)
        memwit_size.append(float(measurement[12]))
        nonmemwit_size.append(float(measurement[13]))

    return Measurements(insertion_times, k, memqueries_proof_times, memqueries_verify_times, nonmemqueries_proof_times,
                        nonmemqueries_verify_times, nonmemwit_size, ns, sec)


run_rsa_benchmarks_bulk(60)
# cProfile.run("run_rsa_benchmarks_bulk()")
# read_filesingle(20)
