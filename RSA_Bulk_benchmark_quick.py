import time
from copy import deepcopy
from random import shuffle

from RSAAccumulator import generate_safe_RSA_modulus, Accumulator, AccumulatorNoU, verify_membership
from prime_hash import PrimeHashv2


def run_bench(h, label, acc_og):
    interval = 10000
    n = interval * 10

    bulks_lens = 2
    reps = 2
    f = open("bulk_membership.txt", "a")
    bulk_membership_gen = [[0 for _ in range(bulks_lens)] for _ in range(int(n/interval))]  # 100, 1000, 10000? n
    bulk_membership_ver = [[0 for _ in range(bulks_lens)] for _ in range(int(n/interval))]  # 100, 1000, 10000? n
    insertion_times = [0 for _ in range(int(n/interval))]
    for k in range(reps):
        inserted_elements = []
        acc = deepcopy(acc_og)
        for i in range(0, n, interval):
            iters = i + interval
            m = int(i/interval)
            print(iters, label, m)
            to_insert = []
            for j in range(i, i+interval):
                to_insert.append(h.prime_hash(j))
            start_time = time.time()
            for ele in to_insert:
                inserted_elements.append(ele)
                acc.insert(ele)
            end_time = time.time()
            insertion_times[m] += (end_time - start_time)/reps
            bulk_sizes = [100, len(inserted_elements)]
            #print(len(inserted_elements))
            #shuffle(inserted_elements)
            for idx in range(bulks_lens):
                start_time = time.time()
                witnesses = acc.get_bulk_membership(inserted_elements[:bulk_sizes[idx]])
                end_time = time.time()
                bulk_membership_gen[m][idx] += (end_time - start_time)/reps
                start_time = time.time()
                for x, w in witnesses:
                    assert verify_membership(x, w, acc.acc, acc.n)
                end_time = time.time()
                bulk_membership_ver[m][idx] += (end_time - start_time) / reps
    tkst = ""
    for timeb in bulk_membership_gen:
        tkst += str(timeb) + "; "
    tkst += "|"
    for timeb in bulk_membership_ver:
        tkst += str(timeb) + "; "
    f.write(tkst + "ø " + label + "\n")
    f.write(insertion_times.__str__() + "\n")
    print(insertion_times)


def run():
    print("Generating safe RSA modulus")
    rsa_modulus, p, q = generate_safe_RSA_modulus(2048)
    print("Generation done")
    acc1 = Accumulator(2048, rsa_modulus)
    acc2 = AccumulatorNoU(2048, rsa_modulus)
    hash40 = PrimeHashv2(40)
    hash80 = PrimeHashv2(80)
    run_bench(hash40, "hash40acc2", acc2)
    run_bench(hash80, "hash80acc2", acc2)
    #run_bench(hash40, "hash40acc1", acc1)
    #run_bench(hash80, "hash80acc1", acc1)
run()