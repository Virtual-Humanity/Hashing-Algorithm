"""Start of the program """
import os
import re
import sys
import string
import random
import hashlib


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
            user_string = input('Enter a string please: ')
        except EOFError:
            sys.exit()
        print('String inputted: ')
        encrypt_stuff = hashfunction(user_string)
        print('---')
        result = brute_force(encrypt_stuff)
        print('Number of steps taken:')
        print(result)


if __name__ == '__main__':
    main()
