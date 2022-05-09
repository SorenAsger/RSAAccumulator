

# First run with basic (non-bulk) accumulator

# Benchmarks hash function times
# Benchmark safe prime time

# Benchmark RSA accumulator for hash size 40 and 80
# Here we will be doing 10 witnesses for membership and nonmembership

# Benchmark bulk witnesses - here show time to precompute n membership witnesses
# and n nonmembership witnesses.

# Then also show for bulk 10, 100, 1000 membership and 10, 100, 1000 nonmembership

# Prod pow benchmark
import sys
import timeit
from random import random

from RSAAccumulator import PrimeHashv2, Accumulator, generate_safe_RSA_modulus


def get_avg_time(n, interval_length, function, random_writes=False, input_factor=1):
    y_values = []
    x_values = []

    for j in range(1, n, interval_length):

        start = timeit.default_timer()
        for i in range(j, j + interval_length):
            if random_writes:
                function(input_factor * random.randint(0, 2 ** 32))
            else:
                function(i)
        end = timeit.default_timer()

        avg_y = ((end - start) / interval_length)

        y_values.append(avg_y)
        x_values.append(j)

    return x_values, y_values


# Here we define functions to benchmark
h40 = PrimeHashv2(40)
h80 = PrimeHashv2(80)
rsa_modulus = generate_safe_RSA_modulus()
acc1 = Accumulator(rsa_modulus)
def RSABenchmarkhash60(x):
    hval = h40.prime_hash(x)


