import hashlib
from random import shuffle


class TestObject:

    def __init__(self, val):
        self.val = val

    def __lt__(self, other):
        return self.val < other.val

    def __le__(self, other):
        return self.val <= other.val

    def bytes(self):
        # does not really matter
        return self.val.to_bytes(16, byteorder='big')


class MerkleInternalNode:

    def search_rule(self, obj):
        return obj < self.right.min

    def not_in_subtree(self, obj):
        return self.left.max < obj < self.right.min

    def __init__(self, left, right):
        self.left = left
        self.right = right
        m = hashlib.sha256()
        m.update(left.hash)
        m.update(right.hash)
        self.hash = m.digest()
        self.min = left.min
        self.max = right.max

    def insert(self, obj):
        if self.search_rule(obj):
            self.left = self.left.insert(obj)
            self.min = self.left.min
        else:
            self.right = self.right.insert(obj)
            self.max = self.right.max
        m = hashlib.sha256()
        m.update(self.left.hash)
        m.update(self.right.hash)
        self.hash = m.digest()
        return self

    def search(self, obj, path):
        path_hashes = (self.hash, self.left.hash, self.right.hash)
        # should check subtree status, if smaller, then proof is just the path to the left most node in the subtree
        # actually smaller and bigger is only a case for the root to see
        # Otherwise it will be inbetween some subtrees and then the proof will be the right path of the left node and the left path of the right node
        # so really we are only interested in if it is in-between
        # if it is in between we know it is not in the sub-tree and thus we search down the paths for the left max and the right min
        # should really make the path an object
        path.append(path_hashes)
        if self.not_in_subtree(obj):
            # element is in between, so we get two new paths one for left and one for right side
            return False, (path, (self.left.search(self.left.max, []), self.right.search(self.right.min, [])))
        if self.search_rule(obj):
            return self.left.search(obj, path)
        return self.right.search(obj, path)


class MerkleLeafNode:

    def __init__(self, object):
        self.obj = object
        m = hashlib.sha256()
        m.update(object.bytes())
        self.hash = m.digest()
        self.min = object
        self.max = object

    def insert(self, obj2):
        obj1 = self.obj
        left, right = (obj1, obj2) if (obj1 < obj2) else (obj2, obj1)
        left_leaf = MerkleLeafNode(left)
        right_leaf = MerkleLeafNode(right)
        new_node = MerkleInternalNode(left_leaf, right_leaf)
        return new_node

    def search(self, obj, path):
        # maybe?
        path_hashes = (self.hash)
        path.append(path_hashes)
        return True, path


class MerkleTree:

    def __init__(self, obj1, obj2):
        left, right = (obj1, obj2) if (obj1 < obj2) else (obj2, obj1)
        left_leaf = MerkleLeafNode(left)
        right_leaf = MerkleLeafNode(right)
        self.root = MerkleInternalNode(left_leaf, right_leaf)

    def insert(self, obj):
        self.root = self.root.insert(obj)

    def search(self, obj):
        path_hashes = (self.root.hash, self.root.left.hash, self.root.right.hash)
        # if obj is left of smallest value in database then path to the left is proof that the element is not there
        if obj < self.root.left.min:
            res, path = self.root.left.search(self.root.left.min, [path_hashes])
            return False, path
        # similar but obj to the right
        if self.root.right.max < obj:
            res, path = self.root.right.search(self.root.right.max, [path_hashes])
            return False, path
        return self.root.search(obj, [])

    def checkObject(self, obj):
        # returns bool, witness
        return self.search(obj)


def verify(rootHash, obj, is_in, witness):
    # This verifies a sub-path up to rootHash - can be used for non-membership witness too.
    if is_in:
        # single path
        m = hashlib.sha256()
        m.update(obj.bytes())
        actual_hval = m.digest()
        init_hval = witness[-1]
        if init_hval != actual_hval:
            return False
        plen = len(witness)
        prev_hash = init_hval
        print("plen, ", plen)
        for i in range(2, plen + 1):
            parent, left, right = witness[plen - i]
            print(parent, "\n", left, "\n", right)
            print("AA")
            print(prev_hash)
            print("BB")
            isLeft = prev_hash == left
            print(isLeft)
            m = hashlib.sha256()
            if isLeft:
                m.update(prev_hash)
                m.update(right)
            else:
                m.update(left)
                m.update(prev_hash)
            prev_hash = m.digest()
            if prev_hash != parent:
                m = hashlib.sha256()
                m.update(left)
                m.update(right)
                print("ok", i)
                print(prev_hash)
                print(m.digest())
                print(parent)
                return False
        print(witness[0][0])
        return prev_hash == rootHash
    pass


objects = []
for i in range(100):
    objects.append(TestObject(i))

shuffle(objects)
tree = MerkleTree(objects[0], objects[1])
for i in range(2, 100):
    tree.insert(objects[i])

is_in, witness = tree.checkObject(objects[3])
print(is_in)
print(witness)

rhash = tree.root.hash
print(verify(rhash, objects[3], is_in, witness))
print("rhash, ", rhash)
not_in = TestObject(101)
is_in, witness = tree.checkObject(not_in)
print(is_in)
print(witness)
