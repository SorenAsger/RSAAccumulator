class TestObject:

    def __init__(self, val):
        self.val = val

    def __lt__(self, other):
        return self.val < other.val

    def __le__(self, other):
        return self.val <= other.val

    def __eq__(self, other):
        return self.val == other.val

    def bytes(self):
        # does not really matter
        return self.val.to_bytes(16, byteorder='big')
