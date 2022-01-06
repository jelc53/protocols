import os
import sys

def strxor(a, b):     # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

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
        ciphertext = [c.strip() for c in f.readlines()]

    # xor paris of cipher text msgs
    m01 = strxor(ciphertext[0], ciphertext[1])
    m23 = strxor(ciphertext[2], ciphertext[3])
    m45 = strxor(ciphertext[4], ciphertext[5])
    m67 = strxor(ciphertext[6], ciphertext[7])
    m89 = strxor(ciphertext[8], ciphertext[9])
    
    print(ciphertext[0])
    
    


if __name__ == '__main__':
    main()
