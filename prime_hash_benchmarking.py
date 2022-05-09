import random
import time

from prime_hash import PrimeHashv2, PrimeHash
import matplotlib.pyplot as plt


def hash_to_collision(prime_hash, rand_num=True):
    hash_map = {}
    i = 0
    while True:
        if rand_num:
            num = random.randint(2 ** (128 - 1), 2 ** 128)
        else:
            num = i
        hval = (prime_hash.prime_hash(num))
        if hash_map.__contains__(hval):
            return i
        hash_map[hval] = 1
        i += 1
        # print(i)
        # print(len(hash_map))
        if len(hash_map) < i:
            return i


def test_prime_hash1():
    reps = 20
    secs = [46 + i for i in range(2)]
    measurements = []
    for sec in secs:
        iterations = []
        for _ in range(reps):
            print(f"Testing {sec}")
            prime_hash1 = PrimeHashv2(sec)
            iterations_before_collision = hash_to_collision(prime_hash1)
            print(iterations_before_collision)
            iterations.append(iterations_before_collision)
        measurements.append((sec, sum(iterations) / reps))
    return measurements


def test_prime_hash_time(prime_hash, queries):
    nums = [random.randint(2 ** (128 - 1), 2 ** 128) for _ in range(queries)]
    start_time = time.time()
    for num in nums:
        prime_hash.prime_hash(num)
    return time.time() - start_time


def test_time_primev1():
    bit_lengths = [i for i in range(12, 60)]
    f = open("prime_hash_time.txt", "a")
    f.write("--START HASH BENCHMARK--\n")
    reps = 20
    for bit_length in bit_lengths:
        measurements = []
        for rep in range(reps):
            print(f"Testing length: {bit_length}")
            hsh = PrimeHash(bit_length)
            time_elapsed = test_prime_hash_time(hsh, 1000)
            measurements.append(time_elapsed)
        f.write(f"{bit_length}, {sum(measurements)/reps}\n")
    f.close()


def test_time_primev2():
    bit_lengths = [i for i in range(28, 256, 2)]
    f = open("prime_hash_timev2.txt", "a")
    f.write("--START HASH BENCHMARK--\n")
    reps = 20
    for bit_length in bit_lengths:
        measurements = []
        for rep in range(reps):
            print(f"Testing length: {bit_length}")
            hsh = PrimeHashv2(bit_length)
            time_elapsed = test_prime_hash_time(hsh, 1000)
            measurements.append(time_elapsed)
        f.write(f"{bit_length}, {sum(measurements)/reps}\n")
    f.close()


def read_file():
    f = open("hashbenchmarks.txt", "r")
    # lines = f.readlines()
    lines = f.read()
    lines = lines.replace("--END HASH BENCHMARK--\n", "")
    measurements = lines.split("--START HASH BENCHMARK--\n")
    ks = []
    avgs = []
    for measurement in measurements[1].split("\n")[:-1]:
        s = measurement.split(", ")
        # print(s)
        # print(s[0])
        k = int(s[0])
        avg = float(s[1])
        ks.append(k)
        avgs.append(avg)
    plt.title("Hashes before collision")
    plt.xlabel("Bitlength of hash")
    plt.yscale("log")
    plt.ylabel("Average hashes before collision")
    plt.plot(ks, avgs)
    plt.show()


def read_file_hash_time(filename, title, idx=1):
    f = open(filename, "r")
    lines = f.read().split("--START HASH BENCHMARK--\n")
    ks = []
    avgs = []
    for measurement in lines[idx].split("\n")[:-1]:
        s = measurement.split(", ")
        k = int(s[0])
        avg = float(s[1])
        ks.append(k)
        avgs.append(avg)
    plt.title(f"Hash performance for {title}")
    plt.xlabel("Bitlength of hash")
    plt.ylabel("Time for 1000 hashes")
    plt.plot(ks, avgs)
    plt.show()


def run_hash_benchmark():
    measurement = test_prime_hash1()
    f = open("hashbenchmarks.txt", "a")
    f.write("--START HASH BENCHMARK--\n")
    for sec, m in measurement:
        f.write(f"{sec}, {m}\n")
    f.write("--END HASH BENCHMARK--\n")
    f.close()


read_file()

#test_time_primev1()
#test_time_primev2()
read_file_hash_time("prime_hash_time.txt", "first hash", 6)
read_file_hash_time("prime_hash_timev2.txt", "second hash", 3)
