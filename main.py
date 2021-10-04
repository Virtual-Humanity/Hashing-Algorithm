""" Hashing Algorithm """
# Implementation of a SHA based hashing algorithm
# As defined in FIPS 180-4
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
"""Hash Function should output: a random output bit vector y of length 32 bits.
 Use only logical operators (&, |, >>, <<) and Rotate right/left to generate the output (digest).
 May take ideas from how existing Hash functions like SHA-2 are designed. 
"""
"""Start of the program """

import os
import re
import sys
import math
import string
import random
import hashlib

""" Environment Setup """
# CONSTANTS, FIPS 180-4 4.2.2
# Sixty-four constant 32-bit words representing the first 32 bits of the fractional parts of
# the cube roots of the first sixty-four prime numbers. In hex, these constant words are:
'''k = [0x428a, 0x7137, 0xb5c0, 0xe9b5, 0x3956, 0x59f1, 0x923f, 0xab1c,
     0xd807, 0x1283, 0x2431, 0x550c, 0x72be, 0x80de, 0x9bdc, 0xc19b,
     0xe49b, 0xefbe, 0x0fc1, 0x240c, 0x2de9, 0x4a74, 0x5cb0, 0x76f9,
     0x983e, 0xa831, 0xb003, 0xbf59, 0xc6e0, 0xd5a7, 0x06ca, 0x1429,
     0x27b7, 0x2e1b, 0x4d2c, 0x5338, 0x650a, 0x766a, 0x81c2, 0x9272,
     0xa2bf, 0xa81a, 0xc24b, 0xc76c, 0xd192, 0xd699, 0xf40e, 0x106a,
     0x19a4, 0x1e37, 0x2748, 0x34b0, 0x391c, 0x4ed8, 0x5b9c, 0x682e,
     0x748f, 0x78a5, 0x84c8, 0x8cc7, 0x90be, 0xa450, 0xbef9, 0xc671]'''
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
def pad_and_parse(message):
    hash_array = bytearray(message, 'utf8')
    #print(hash_array)
    message_bit_length = (8 * len(hash_array)) & 0xFFFFFFFFFFFFFFFF
    #print('Bit Length:')
    #print(message_bit_length)
    # Pad with zeros out to 448 bits, ( L + 1 + K ) mod 512 = 448
    while len(hash_array) % 64 != 56:
        hash_array.append(0)
    # Append original message length in bits mod (2^64)
    hash_array += message_bit_length.to_bytes(8, byteorder='big')

    """N = math.ceil(len(data) / 4)  # number of 4-integer (32-bit) blocks required to hold 'l' ints
    M = bytearray(N)  # message M is N×4 array of 32-bit integers
"""
    return hash_array

def hash_function(decrypted_m):
    """Hash function that will encrypt a message """
    """Output: a random output bit vector y of length 32 bits.
     Use only logical operators (&, |, >>, <<) and Rotate right/left to generate the output (digest).
     May take ideas from how existing Hash functions like SHA-2 are designed. 
    """
    # 3. Set the Initial Hash Value
    "The first 32 bits of the fractional parts of the first 8 primes' square roots "
    h0, h1, h2, h3, h4, h5, h6, h7 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, \
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    length_string = len(decrypted_m)
    # Below is converting the string into binary notation
    print('Binary Form:')
    binary_num = ''.join(format(ord(i), '08b') for i in decrypted_m)
    print(binary_num)

    print('\nHexadecimal Form:')
    # converting binary form to hexadecimal form
    hex_num = hex(int(binary_num))
    print(hex_num)
    hash_array = pad_and_parse(hex_num)
    # Process the message in 512-bit chunks:
    for offset in range(0, len(hash_array), 64):
        chunks = hash_array[offset: offset + 64]
        # Breaks chunks into 32-bit words
        words = [0 for i in range(64)]
        for i in range(16):
            words[i] = int.from_bytes(chunks[4 * i: 4 * i + 4], byteorder='big')
        # Extend the first 16 words, distributing them across the rest
    #    print('Words:')
        for i in range(16, 64):
            s0 = ((words[i - 15] >> 7) ^ (words[i - 15] >> 18) ^ (words[i - 15] >> 3)) & 0xFFFFFFFF
            s1 = ((words[i - 2] >> 17) ^ (words[i - 2] >> 19) ^ (words[i - 2] >> 10)) & 0xFFFFFFFF
            words[i] = (words[i - 16] + s0 + words[i - 7] + s1) & 0xFFFFFFFF
    #    print(words)
        # Initialize the hash value
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        # Hash loop, https://tools.ietf.org/html/rfc6234
        for i in range(64):
            S1 = ((e >> 6) ^ (e >> 11) ^ (e >> 25)) & 0xFFFFFFFF
            ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFF
            temp1 = (h + S1 + ch + k[i] + words[i]) & 0xFFFFFFFF
            S0 = ((a >> 2) ^ (a >> 13) ^ (a >> 22)) & 0xFFFFFFFF
            maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
            temp2 = (S0 + maj) & 0xFFFFFFFF

            new_a = (temp1 + temp2) & 0xFFFFFFFF
            new_e = (d + temp1) & 0xFFFFFFFF
            # Rotate the 8 variables
            a, b, c, d, e, f, g, h = new_a, a, b, c, new_e, e, f, g

        # Add each set of results to the running total hash:
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    # Output
    hash_pieces = [h0, h1, h2, h3, h4, h5, h6, h7]
    #print('Hash Pieces:')
    #print(hash_pieces)
    # h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
    hashed_output = hex(sum(hash_pieces[::-1]) & 0xFFFFFFFF )      #(x << (32 * i))
    #print(hashed_output)
    # Below is just showing encryption of sha224
    # encoded_m = decrypted_m.encode()
    # hash_obj_sha256 = hashlib.sha256(encoded_m)
    # print(hash_obj_sha256)
    # print(hash_obj_sha224.hex_digest())

    return hashed_output


def brute_force(encrypt_m):
    """Function that will run a brute force attack to find collisions """

    # this brute list will contain the random string that will be generated
    brute_list = ''
    i = 0

    # variable below will keep track of the number of randomly generated strings have been created
    num_steps = 0

    # list_sol will be a list that will contain all of the possibilities of characters or numbers that are in a
    # hexadecimal form

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
        while True:
            try:
                user_string = input('Enter a string to hash: ')
                if not user_string:
                    raise ValueError('No input')
                break
            except ValueError as e:
                print(e)
        hashed_result = hash_function(user_string)
        print('\nOriginal Message Input and its Hashed Output: ')
        print(user_string, ':\t', hashed_result)
        print('---')
        # result = brute_force(hashed_result)
        print('\nNumber of steps to find a collision:')
    # print(result)


if __name__ == '__main__':
    main()

'''
examples
FIPS 180-4 Implementation Specification
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

https://www.movable-type.co.uk/scripts/sha256.html

https://perso.crans.org/besson/publis/notebooks/Manual_implementation_of_some_hash_functions.html#The-SHA2-class
'''
