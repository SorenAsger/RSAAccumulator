import hashlib

from MerkleTree import Witness


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


def verify(rootHash, witness: Witness):
    # This verifies a sub-path up to rootHash - can be used for non-membership witness too.
    obj, wpath = witness.primary_path
    if witness.is_member:
        return verify_subpath(rootHash, objHash(obj), wpath, None)
    # Different cases, either the element is not in the tree and is larger than max, or smaller than min
    # Or it is not in the tree but the value is between max and min values.
    if witness.primary_path is not None and witness.left_path is not None and witness.right_path is not None:
        # there are more paths here
        lobj, lwpath = witness.left_path
        robj, rwpath = witness.right_path
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
        if witness.left_path is None and witness.right_path is None:
            return False
        if witness.left_path is None:
            robj, rpath = witness.right_path
            if obj < robj:
                return False
            return verify_subpath(rootHash, objHash(robj), rpath, False)
        lobj, lpath = witness.left_path
        if lobj < obj:
            return False
        return verify_subpath(rootHash, objHash(lobj), lpath, True)