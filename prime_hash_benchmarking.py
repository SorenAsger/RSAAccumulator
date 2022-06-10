import random
import time

from prime_hash import RandomOraclePrimeHash, PrimeHash
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
            prime_hash1 = RandomOraclePrimeHash(sec)
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
        avg_length =sum(hsh.prime_map.values())/len(hsh.prime_map)
        print(avg_length)
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
            hsh = RandomOraclePrimeHash(bit_length)
            time_elapsed = test_prime_hash_time(hsh, 1000)
            measurements.append(time_elapsed)
        avg_length =sum(hsh.prime_map.values())/len(hsh.prime_map)
        print(avg_length)
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
        avgs.append(avg / 1000)
    plt.title(f"Avg. hash time for {title}")
    plt.xlabel("k - approximately the bit-length of the output")
    plt.ylabel("seconds")
    plt.ticklabel_format(axis="y", style="sci", scilimits=(0, 0))
    plt.plot(ks, avgs)
    plt.savefig(title)
    plt.show()


def run_hash_benchmark():
    measurement = test_prime_hash1()
    f = open("hashbenchmarks.txt", "a")
    f.write("--START HASH BENCHMARK--\n")
    for sec, m in measurement:
        f.write(f"{sec}, {m}\n")
    f.write("--END HASH BENCHMARK--\n")
    f.close()


#read_file()

#test_time_primev1()
test_time_primev2()
#read_file_hash_time("prime_hash_time.txt", "universal prime hash", 2)
#read_file_hash_time("prime_hash_timev2.txt", "random oracle prime hash", 1)
