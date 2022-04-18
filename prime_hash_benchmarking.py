import random

from RSAAccumulator import PrimeHash, PrimeHashv2


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
        #print(i)
        #print(len(hash_map))
        if len(hash_map) < i:
            return i


def test_prime_hash1():
    reps = 10
    secs = [12 + i for i in range(40)]
    measurements = []
    for sec in secs:
        iterations = []
        for _ in range(reps):
            print(f"Testing {sec}")
            prime_hash1 = PrimeHashv2(sec)
            iterations_before_collision = hash_to_collision(prime_hash1)
            print(iterations_before_collision)
            iterations.append(iterations_before_collision)
        measurements.append((sec,sum(iterations) / reps))
    return measurements

measurement = test_prime_hash1()

f = open("hashbenchmarks.txt", "a")
f.write("--START HASH BENCHMARK--\n")
to_write = ""
for sec, m in measurement:
    f.write(f"{sec}, {m}\n")
f.write("--END HASH BENCHMARK--\n")
f.close()
