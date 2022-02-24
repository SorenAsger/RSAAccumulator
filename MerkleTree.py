import hashlib


class PathElement:
    def __init__(self, is_left, hsh):
        self.is_left = is_left
        self.hash = hsh


class Path:
    def __init__(self, obj, path_to_obj):
        pass


class Witness:
    def __init__(self, is_member, primary_path, left_path, right_path):
        self.right_path = right_path
        self.left_path = left_path
        self.is_member = is_member
        self.primary_path = primary_path
        # primary path is path to member node, in case of non-membership it is a path to split node
        # Left path and right path only exists in case of split node.
        # In such case left path is the all right path of the left subtree and vice versa for right path


class MerkleNodeInterface:

    def __init__(self):
        self.hash = None
        self.min = None
        self.max = None

    def search(self, obj, path) -> Witness:
        raise NotImplementedError

    def insert(self, obj) -> 'MerkleNodeInterface':
        raise NotImplementedError

    def delete(self, obj) -> 'MerkleNodeInterface':
        raise NotImplementedError


class MerkleInternalNode(MerkleNodeInterface):

    def delete(self, obj) -> 'MerkleNodeInterface':
        if self.not_in_subtree(obj):
            return self # element cannot be deleted because it is not in the sub-tree
        if type(self.right) is MerkleLeafNode and self.right.obj is obj:
            return self.left
        if type(self.left) is MerkleLeafNode and self.left.obj is obj:
            return self.right
        if self.search_rule(obj):
            return self.left.delete(obj)
        else:
            return self.right.delete(obj)

    def search_rule(self, obj):
        return obj < self.right.min

    def not_in_subtree(self, obj):
        return self.left.max < obj < self.right.min

    def __init__(self, left: MerkleNodeInterface, right: MerkleNodeInterface):
        super().__init__()
        self.left: MerkleNodeInterface = left
        self.right: MerkleNodeInterface = right
        self.update_hash()
        self.min = left.min
        self.max = right.max

    def update_hash(self):
        m = hashlib.sha256()
        m.update(self.left.hash)
        m.update(self.right.hash)
        self.hash = m.digest()

    def insert(self, obj):
        if self.search_rule(obj):
            self.left = self.left.insert(obj)
            self.min = self.left.min
        else:
            self.right = self.right.insert(obj)
            self.max = self.right.max
        self.update_hash()
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
            return Witness(False, (obj, path), lw.primary_path, rw.primary_path)
        if self.search_rule(obj):
            return self.left.search(obj, path)
        return self.right.search(obj, path)


class MerkleLeafNode(MerkleNodeInterface):

    def __init__(self, obj):
        super().__init__()
        self.obj = obj
        m = hashlib.sha256()
        m.update(obj.bytes())
        self.hash = m.digest()
        self.min = obj
        self.max = obj

    def insert(self, obj2):
        obj1 = self.obj
        left, right = (obj1, obj2) if (obj1 < obj2) else (obj2, obj1)
        left_leaf = MerkleLeafNode(left)
        right_leaf = MerkleLeafNode(right)
        new_node = MerkleInternalNode(left_leaf, right_leaf)
        return new_node


    def search(self, obj, path) -> Witness:
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
            return Witness(False, (obj, []), lw.primary_path, None)
        # similar but obj to the right
        if self.root.right.max < obj:
            rw = self.root.right.search(self.root.right.max, [path_hashes])
            return Witness(False, (obj, []), None, rw.primary_path)
        return self.root.search(obj, [])

    def checkObject(self, obj):
        # returns bool, witness
        return self.search(obj)





