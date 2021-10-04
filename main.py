""" Hashing Algorithm """
# Implementation of a SHA based hashing algorithm
# As defined in FIPS 180-4
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
"""Start of the program """

import os
import re
import sys
import string
import random
import hashlib

""" Environment Setup """
# CONSTANTS, FIPS 180-4 4.2.2
# Sixty-four constant 32-bit words representing the first 32 bits of the fractional parts of
# the cube roots of the first sixty-four prime numbers. In hex, these constant words are:
k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


""" Preprocessing """
# 1. Pad the Message to ensure it's a multiple of 32 and
# 2. Parse the Message into 'N' m-bit blocks
def padAndParse(message):
    data = bytearray(message, 'utf8')
    orig_len_in_bits = (8 * len(data)) & 0xFFFFFFFF
    print('Bit Length:')
    print(orig_len_in_bits)
    # Add a 1 bit to the end
    data.append(0x80)
    # Pad with zeros out to 32 bits
    N = math.ceil(len(data)/4)     # number of 4-integer (32-bit) blocks required to hold 'l' ints
    print('N:')
    print(N)
    M = bytearray(N)               # message M is N×4 array of 32-bit integers
    print('M:')
    print(M)

# 3. Set the Initial Hash Value
'''The first 32 bits of the fractional parts of the first 8 primes' square roots '''
h0 = 0x6a09e667
h1 = 0xbb67ae85
h2 = 0x3c6ef372
h3 = 0xa54ff53a
h4 = 0x510e527f
h5 = 0x9b05688c
h6 = 0x1f83d9ab
h7 = 0x5be0cd19

def hashfunction(decrypted_m):
    """Hash function that will encrpyt a message """
    """Output: a random output bit vector y of length 32 bits.
     Use only logical operators (&, |, >>, <<) and Rotate right/left to generate the output (digest).
     May take ideas from how existing Hash functions like SHA-2 are designed. 
    """
    length_string = len(decrypted_m)
    # Below is converting the string into binary notation
    print('Binary Form:')
    binary_num = ''.join(format(ord(i), '08b') for i in decrypted_m)
    print(binary_num)

    print('\nHexadecimal Form:')
    # converting binary form to hexadecimal form
    hex_num = hex(int(binary_num))
    print(hex_num)

    padAndParse(decrypted_m)

    # Below is just showing encryption of sha224
    # decrypted_m = decrypted_m.encode()
    # hash_obj_sha224 = hashlib.sha224(decrypted_m)
    # print(hash_obj_sha224.hexdigest())

    return binary_num

def brute_force(encrypt_m):
    """Function that will run a brute force attack to find collisions """

    # this brute list will contain the random string that will be generated
    brute_list = ''
    i = 0

    # variable below will keep track of the number of randomly generated strings have been created
    num_steps = 0

    # list_sol will be a list that will contain all of the possibilites of characters or numbers that are in a hexadecimal form

    list_sol = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'x']
    while i == 0:
        brute_list = ''
        for x in range(len(encrypt_m)):  # the number in the range will be the length of the string
            # letter = string.ascii_letters
            random_letter = random.choice(list_sol)  # random letter/number will be selected
            brute_list = brute_list[:x] + random_letter + brute_list[
                                                          x:]  # random letter/number will be added to brute_list

        if brute_list == encrypt_m:
            # if brute list is equal to the encrypted message, then brute force worked successfully
            i == 1
            return num_steps  # returning the number of steps it took to generate the correct string
        num_steps += 1


def main():
    """Main function """
    while True:
        try:
            user_string = input('Enter a string to hash: ')
        except EOFError:
            sys.exit()
        print('String inputted: ')
        hashed_stuff = hashfunction(user_string)
        print('---')
      #  result = brute_force(hashed_stuff)
        print('Number of steps taken:')
      #  print(result)


if __name__ == '__main__':
    main()

'''
examples
FIPS 180-4 Implementation Specification
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

https://www.movable-type.co.uk/scripts/sha256.html

https://perso.crans.org/besson/publis/notebooks/Manual_implementation_of_some_hash_functions.html#The-SHA2-class

    def __init__(self):
        self.name = "SHA256"
        self.byteorder = 'big'
        self.block_size = 64
        self.digest_size = 32
        # Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
        # Note 3: The compression function uses 8 working variables, a through h
        # Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
        #         and when parsing message block data from bytes to words, for example,
        #         the first word of the input message "abc" after padding is 0x61626380

        # Initialize hash values:
        # (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h4 = 0x510e527f
        h5 = 0x9b05688c
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19

        # Initialize array of round constants:
        # (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        # Store them
        self.hash_pieces = [h0, h1, h2, h3, h4, h5, h6, h7]


    def update(self, arg):
        h0, h1, h2, h3, h4, h5, h6, h7 = self.hash_pieces
        # 1. Pre-processing, exactly like MD5
        data = bytearray(arg)
        orig_len_in_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
        # 1.a. Add a single '1' bit at the end of the input bits
        data.append(0x80)
        # 1.b. Padding with zeros as long as the input bits length ≡ 448 (mod 512)
        while len(data) % 64 != 56:
            data.append(0)
        # 1.c. append original length in bits mod (2 pow 64) to message
        data += orig_len_in_bits.to_bytes(8, byteorder='big')
        assert len(data) % 64 == 0, "Error in padding"
        # 2. Computations
        # Process the message in successive 512-bit = 64-bytes chunks:
        for offset in range(0, len(data), 64):
            # 2.a. 512-bits = 64-bytes chunks
            chunks = data[offset: offset + 64]
            w = [0 for i in range(64)]
            # 2.b. Break chunk into sixteen 32-bit = 4-bytes words w[i], 0 ≤ i ≤ 15
            for i in range(16):
                w[i] = int.from_bytes(chunks[4 * i: 4 * i + 4], byteorder='big')
            # 2.c.  Extend the first 16 words into the remaining 48
            #       words w[16..63] of the message schedule array:
            for i in range(16, 64):
                s0 = (rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ rightshift(w[i - 15], 3)) & 0xFFFFFFFF
                s1 = (rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ rightshift(w[i - 2], 10)) & 0xFFFFFFFF
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
            # 2.d. Initialize hash value for this chunk
            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
            # 2.e. Main loop, cf. https://tools.ietf.org/html/rfc6234
            for i in range(64):
                S1 = (rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)) & 0xFFFFFFFF
                ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFF
                temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
                S0 = (rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)) & 0xFFFFFFFF
                maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
                temp2 = (S0 + maj) & 0xFFFFFFFF

                new_a = (temp1 + temp2) & 0xFFFFFFFF
                new_e = (d + temp1) & 0xFFFFFFFF
                # Rotate the 8 variables
                a, b, c, d, e, f, g, h = new_a, a, b, c, new_e, e, f, g

            # Add this chunk's hash to result so far:
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
            h5 = (h5 + f) & 0xFFFFFFFF
            h6 = (h6 + g) & 0xFFFFFFFF
            h7 = (h7 + h) & 0xFFFFFFFF
        # 3. Conclusion
        self.hash_pieces = [h0, h1, h2, h3, h4, h5, h6, h7]


    def digest(self):
        # h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
        return sum(leftshift(x, 32 * i) for i, x in enumerate(self.hash_pieces[::-1]))
    '''
