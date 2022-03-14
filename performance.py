import cProfile
def test():
    RSABenchmark(2000, 1000, 1000, 5, security=256)
def test2():
    MerkleTreeBenchmark(10000, 1000, 1000, 5)
from Benchmarking import RSABenchmark, MerkleTreeBenchmark
cProfile.run("test()")
#test()
test2()