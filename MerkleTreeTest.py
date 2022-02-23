import unittest
from random import shuffle

from MerkleTree import MerkleTree
from TestObject import TestObject
from Verification import verify

def construct_tree():
    # Contain even elements from 0 to 198 inclusive
    objects = []
    for i in range(100):
        objects.append(TestObject(i * 2))

    shuffle(objects)
    tree = MerkleTree(objects[0], objects[1])
    for i in range(2, 100):
        tree.insert(objects[i])
    return tree


class MerkleTreeTests(unittest.TestCase):
    def test_membership(self):
        tree = construct_tree()
        obj = TestObject(8)  # Even numbers should be in tree
        witness = tree.checkObject(obj)
        assert witness.is_member
        assert verify(tree.root.hash, witness)

    def test_nonmembership(self):
        tree = construct_tree()
        obj = TestObject(9)  # Odd numbers should not be in tree
        witness = tree.checkObject(obj)
        assert not witness.is_member
        assert verify(tree.root.hash, witness)

not_in = TestObject(222)


if __name__ == '__main__':
    unittest.main()
