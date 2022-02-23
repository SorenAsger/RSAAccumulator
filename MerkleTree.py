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

class Witness:
    def __init__(self, val, primpath, lpath, rpath):
        self.rpath = rpath
        self.lpath = lpath
        self.val = val
        self.primpath = primpath


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

    def search(self, obj, path) -> Witness:
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
            lw, rw = self.left.search(self.left.max, []), self.right.search(self.right.min, [])
            return Witness(False, (obj, path), lw.primpath, rw.primpath)
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

    def search(self, obj, path) -> Witness:
        # maybe?
        path_hashes = self.hash
        path.append(path_hashes)
        return Witness(True, (obj, path), None, None)


class MerkleTree:

    def __init__(self, obj1, obj2):
        left, right = (obj1, obj2) if (obj1 < obj2) else (obj2, obj1)
        left_leaf = MerkleLeafNode(left)
        right_leaf = MerkleLeafNode(right)
        self.root = MerkleInternalNode(left_leaf, right_leaf)

    def insert(self, obj):
        self.root = self.root.insert(obj)

    def search(self, obj) -> Witness:
        path_hashes = (self.root.hash, self.root.left.hash, self.root.right.hash)
        # if obj is left of smallest value in database then path to the left is proof that the element is not there
        if obj < self.root.left.min:
            lw = self.root.left.search(self.root.left.min, [path_hashes])
            return Witness(False, (obj, []), lw.primpath, None)
        # similar but obj to the right
        if self.root.right.max < obj:
            rw = self.root.right.search(self.root.right.max, [path_hashes])
            return Witness(False, (obj, []), None, rw.primpath)
        return self.root.search(obj, [])

    def checkObject(self, obj):
        # returns bool, witness
        return self.search(obj)

def verify_subpath(rootHash, objHash, witness_path, must_be_left):
    init_hval = witness_path[-1]
    if init_hval != objHash:
        return False
    plen = len(witness_path)
    prev_hash = init_hval
    for i in range(2, plen + 1):
        parent, left, right = witness_path[plen - i]
        isLeft = prev_hash == left
        if must_be_left is not None:  # this is to check direction of path is right
            if not must_be_left == isLeft:
                return False
        m = hashlib.sha256()
        if isLeft:
            m.update(prev_hash)
            m.update(right)
        else:
            m.update(left)
            m.update(prev_hash)
        prev_hash = m.digest()
        if prev_hash != parent:
            return False
    return prev_hash == rootHash

def objHash(obj):
    m = hashlib.sha256()
    m.update(obj.bytes())
    return m.digest()

def verify(rootHash, witness : Witness):
    # This verifies a sub-path up to rootHash - can be used for non-membership witness too.
    obj, wpath = witness.primpath
    if witness.val:
        return verify_subpath(rootHash, objHash(obj), wpath, None)
    # Different cases, either the element is not in the tree and is larger than max, or smaller than min
    # Or it is not in the tree but the value is between max and min values.
    if witness.primpath is not None and witness.lpath is not None and witness.rpath is not None:
        # there are more paths here
        lobj, lwpath = witness.lpath
        robj, rwpath = witness.rpath
        # This is not good enough, does not check adjacency
        if not lobj < obj < robj:
            return False
        split_node_hash = wpath[-1][0]
        split_node_left = wpath[-1][1]
        split_node_right = wpath[-1][2]
        m = hashlib.sha256()
        m.update(split_node_left)
        m.update(split_node_right)
        if m.digest() != split_node_hash:
            return False
        wpathmodified = wpath[:-1]
        wpathmodified.append(split_node_hash)
        if not verify_subpath(rootHash, split_node_hash, wpathmodified, None):
            return False
        if not verify_subpath(split_node_left, objHash(lobj), lwpath, False):
            return False
        if not verify_subpath(split_node_right, objHash(robj), rwpath, True):
            return False
        return True
    else:
        if witness.lpath is None and witness.rpath is None:
            return False
        if witness.lpath is None:
            robj, rpath = witness.rpath
            if obj < robj:
                return False
            return verify_subpath(rootHash, objHash(robj), rpath, False)
        lobj, lpath = witness.lpath
        if lobj < obj:
            return False
        return verify_subpath(rootHash, objHash(lobj), lpath, True)


objects = []
for i in range(100):
    objects.append(TestObject(i * 2))

shuffle(objects)
tree = MerkleTree(objects[0], objects[1])
for i in range(2, 100):
    tree.insert(objects[i])

witness = tree.checkObject(objects[3])
print(witness.val)

rhash = tree.root.hash
print(verify(rhash, witness))
print("rhash, ", rhash)
not_in = TestObject(99)
witness = tree.checkObject(not_in)
print(witness.val)
print(witness.rpath)
print(witness.lpath)
print(verify(rhash, witness))





not_in = TestObject(222)


