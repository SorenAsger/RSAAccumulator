import random

from MerkleTree import MerkleTree
from TestObject import TestObject


def MerkleTreeBenchmark(iters):
    test_objects = []
    for i in range(iters):
        test_objects.append(TestObject(i))
    random.shuffle(test_objects)
    tree = MerkleTree()