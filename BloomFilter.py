# A BllomFilter implementation referenced from 
# https://bugra.github.io/posts/2016/6/5/a-gentle-introduction-to-bloom-filter/

from bitarray import bitarray
import mmh3

class BloomFilter(set):

    def __init__(self, size, hash_count):
        super(BloomFilter, self).__init__()
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)
        self.size = size
        self.hash_count = hash_count

    def set(self, my_bit_array):
        if len(my_bit_array) != self.size:
            print(f"The size of the input bit array is {len(my_bit_array)}")
            print(f"(expected {self.size})")
            return self
        self.bit_array = my_bit_array
        return self

    def __len__(self):
        return self.size

    def __iter__(self):
        return iter(self.bit_array)

    def add(self, item):
        for ii in range(self.hash_count):
            index = mmh3.hash(item, ii) % self.size
            self.bit_array[index] = 1

        return self

    def seek(self):
        return self.bit_array.search(bitarray('1'))

    def __contains__(self, item):
        out = True
        for ii in range(self.hash_count):
            index = mmh3.hash(item, ii) % self.size
            if self.bit_array[index] == 0:
                out = False

        return out
