import collections
import string
import sys
import os

def strxor(a, b):     # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

def hexxor(a, b):
    return hex(int(a, 16) ^ int(b, 16))
    
def random(size=16):
    return open("/dev/urandom").read(size)

def encrypt(key, msg):
    c = strxor(key, msg)
    print(c.encode('hex'))
    return c

def main():
    # read console args
    input_file = sys.argv[1]
    data_path = os.path.join('hw0', input_file)

    # load ciphertext data
    with open(data_path, 'r') as f:
        ciphers = [str(c.strip()) for c in f.readlines()]
        target = ciphers.pop()

    # xor pairs of cipher text 
    final_key = [None]*150
    known_key_positions = set()

    for i0, c0 in enumerate(ciphers):
        # c0_ascii = bytearray.fromhex(c0).decode("latin1")
        counter = collections.Counter()
        print(len(c0))

        # for each other ciphertext
        for i1, c1 in enumerate(ciphers):
            if i0 != i1:  # don't xor a ciphertext with itself
                # c1_ascii = bytearray.fromhex(c1).decode("latin1")
                m01 = strxor(c0, c1)
                for idxOfChar, char in enumerate(m01):
                    # if a character in xored result is alphanumeric char, there was probably a space character in one of the plaintexts
                    if char in string.printable and char.isalpha(): counter[idxOfChar] += 1  # increment counter at this index

        # find all positions where space character likely in i0 cipher
        knownSpaceIndexes = []
        for ind, val in counter.items():
            # if space found at least 7 times at this index out of 9 possible xors, then likely from i0 cipher
            if val >= 7: knownSpaceIndexes.append(ind)
        
        # xor current_index with spaces
        xor_with_spaces = strxor(c0,' '*150)

        for index in knownSpaceIndexes:
            # store key's value at the correct position
            final_key[index] = xor_with_spaces[index].encode('utf-8')

            # record that we know the key at this position
            known_key_positions.add(index)
    print(final_key)
    # construct a hex key from the currently known key, adding in '00' hex chars where we do not know (to make a complete hex string)
    final_key_hex = ''.join([val.decode('utf-8') if val is not None else '00' for val in final_key])

    # xor the currently known key with the target cipher
    target_ascii = bytearray.fromhex(target).decode("latin1")
    final_key_ascii = bytearray.fromhex(final_key_hex).decode("latin1")
    output = strxor(target_ascii, final_key_ascii)

    # print the output, printing a * if that character is not known yet
    print(''.join([char if index in known_key_positions else '*' for index, char in enumerate(output)]))

    # We then confirm this is correct by producing the key from this, and decrpyting all the other messages to ensure they make grammatical sense
    # target_plaintext = "The secret message is: When using a stream cipher, never use the key more than once"
    # print(target_plaintext)
    # key = strxor(bytearray.fromhex(target).decode('latin1'),target_plaintext)
    # for cipher in ciphers:
    #     print(strxor(bytearray.fromhex(cipher).decode('latin1'),key))
    

if __name__ == '__main__':
    main()
