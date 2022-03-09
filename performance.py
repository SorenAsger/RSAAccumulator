import cProfile
def test():
    RSABenchmark(500, 100, 100, 5, security=60)
from Benchmarking import RSABenchmark
#cProfile.run("test()")
test()