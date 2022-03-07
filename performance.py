import cProfile
def test():
    RSABenchmark(1000, 100, 100, 5, security=60)
from Benchmarking import RSABenchmark
cProfile.run("test()")