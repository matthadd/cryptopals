import random

from set1 import *
import os
import random as rd
from Cryptodome.Cipher import AES
import json

blocksize = 16

# SET 2

# CHALLENGE 9

message_to_pad = b'YELLOW SUBMARINE'
exp_message_to_pad = b"YELLOW SUBMARINE\x04\x04\x04\x04"


def pkcs7(plaintext, blocksize=16):
    pad = (blocksize - len(plaintext) % blocksize) % blocksize
    output_bytes = plaintext
    for _ in range(pad):
        output_bytes += bytes([pad])
    return output_bytes


def strip_pkcs7(plaintext, blocksize=16):
    possible_padding = plaintext[-1]
    for i in range(1, possible_padding + 1):
        if plaintext[-i] != possible_padding:
            return False
    return plaintext[:-possible_padding]


# output_bytes = pkcs7(message_to_pad, 20)
# print(exp_message_to_pad == output_bytes)


# CHALLENGE 10

def AES_encrypt_ECB(key, plaintext, blocksize=16):
    plaintext = pkcs7(plaintext)
    ciphertext = b''
    plain_chunks = [plaintext[i:i + blocksize] for i in range(0, len(plaintext), blocksize)]
    for plainchunk in plain_chunks:
        plain = AES.new(key, AES.MODE_ECB)
        cipherchunk = plain.encrypt(plainchunk)
        ciphertext += cipherchunk
    return ciphertext


def AES_decrypt_ECB(key, ciphertext, blocksize=16):
    ciphertext = pkcs7(ciphertext)
    plaintext = b''
    cipher_chunks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    for cipherchunk in cipher_chunks:
        cipher = AES.new(key, AES.MODE_ECB)
        plainchunk = cipher.decrypt(cipherchunk)
        plaintext += plainchunk
    return plaintext


# key = os.urandom(16)
# print('key:', key)
#
# plaintext  = b'Hello everyone this is a test on my module AES in ECB mode gibberish gibberish hello hello'
# print(len(plaintext), plaintext)
#
# plaintext = pkcs7(plaintext)
# print(plaintext)
#
# ciphertext = AES_encrypt_ECB(key, plaintext)
# print(ciphertext)
#
# plaintext = AES_decrypt_ECB(key, ciphertext)
# print(plaintext)

f = open('10.txt', 'r')
ciphertext = base64.b64decode(f.read())
f.close()
key = b"YELLOW SUBMARINE"


def AES_decrypt_CBC(key, ciphertext, iv=bytes(16), blocksize=16):
    ciphertext = pkcs7(ciphertext)
    plaintext = b''
    precedent_cipherblock = iv
    cipher_chunks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    for cipherblock in cipher_chunks:
        plainblock = xor(AES_decrypt_ECB(key, cipherblock), precedent_cipherblock)
        plaintext += plainblock
        precedent_cipherblock = cipherblock
    return plaintext


# plaintext = AES_decrypt_CBC(key, ciphertext)
# print(plaintext.decode())

def AES_encrypt_CBC(key, plaintext, iv=bytes(16), blocksize=16):
    plaintext = pkcs7(plaintext)
    ciphertext = b''
    precedent_cipherblock = iv
    plain_chunks = [plaintext[i:i + blocksize] for i in range(0, len(plaintext), blocksize)]
    for plainblock in plain_chunks:
        cipherblock = AES_encrypt_ECB(key, xor(plainblock, precedent_cipherblock))
        ciphertext += cipherblock
        precedent_cipherblock = cipherblock
    return ciphertext


def oracle_simple(plaintext, blocksize=16):
    key = os.urandom(blocksize)
    plaintext = os.urandom(rd.randint(5, 10)) + plaintext + os.urandom(rd.randint(5, 10))
    if (rd.randint(0, 1)):
        mode = True
        ciphertext = AES_encrypt_ECB(key, plaintext)
    else:
        mode = False
        ciphertext = AES_encrypt_CBC(key, plaintext)

    return key, ciphertext, mode


def prediction_oracle(ciphertext, blocksize=16):
    """(43, 1.0), (42, 0.906), (41, 0.84), (40, 0.741), (39, 0.684), (38, 0.607), (37, 0.496), (36, 0.523)"""
    cipher_chunks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    for i in range(len(cipher_chunks)):
        for j in range(i + 1, len(cipher_chunks)):
            if cipher_chunks[i] == cipher_chunks[j]:
                return True
    return False


# final_res = []
# for i in range(52):
#     multiple_test = []
#     for _ in range(1000):
#         plaintext = b'A' * (52 - i)
#         key, ciphertext, mode = oracle(plaintext)
#         multiple_test.append(mode == prediction_oracle(ciphertext))
#     res = sum(multiple_test) / len(multiple_test)
#     final_res.append((52 - i, res))
# print(final_res)


def append_oracle(key, plaintext, blocksize=16):
    plaintext += base64.b64decode('''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK''')
    ciphertext = AES_encrypt_ECB(key, plaintext)

    return ciphertext


def attack_on_ECB():
    key = b'&\x97\x06\xe8\x01\xeb\xf8\x08~\xdc\x1aV\xdf*\xb1\\'
    working_block_number = len(append_oracle(key, b''))

    # get the blocksize by the feading the oracle the same bytes
    blocksize = 2
    cipher_chunks = [0, 1]
    while cipher_chunks[0] != cipher_chunks[1]:
        blocksize += 1
        padding = b'A' * (blocksize * 2)
        ciphertext = append_oracle(key, padding)
        cipher_chunks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]

    guess_char = b''  # delete
    guess_chars = b''
    for working_block in range(working_block_number):
        padding = b'A' * (blocksize - 1)
        for j in range(blocksize):
            attack_dict = dict()
            append_padding = padding[j:]
            for i in range(2 ** 8):
                current_append_padding = append_padding + guess_chars + bytes([i])
                cipherblock_i = append_oracle(key, current_append_padding)[
                                working_block * blocksize:blocksize * (1 + working_block)]
                attack_dict[cipherblock_i] = bytes([i])

            cible_cipherblok = append_oracle(key, append_padding)[
                               working_block * blocksize:blocksize * (1 + working_block)]
            guess_char = attack_dict.get(cible_cipherblok, None)
            if guess_char is None:
                return guess_chars
            guess_chars += guess_char
            # print(guess_char.decode(), end = '')

    return guess_chars


# plaintext = attack_on_ECB()
# print(plaintext.decode())

# CHALLENGE 13

def parsing_routine(input_string):
    if isinstance(input_string, str) is False:
        input_string = input_string.decode()
    parsing = input_string.split('&')
    dico = {}
    for element in parsing:
        res = element.split('=')
        dico[res[0]] = res[1]
    return dico


def deparsing_routine(dico):
    return 'email=' + dico['email'] + '&uid=' + dico['uid'] + '&role=' + dico['role']


def profile_for(input_string, key=b'YELLOW SUBMARINE'):
    washup_string = []
    for char in input_string:
        if char is not b'&' and char is not b'=':
            washup_string.append(char)
    washup_string = bytes(washup_string)

    return AES_encrypt_ECB(key, (b'email=' + washup_string + b'&uid=10&role=user'))


def decrypt_profile(profile, key=b'YELLOW SUBMARINE'):
    """Decrypt the encoded user profile and parse it."""
    return parsing_routine(AES_decrypt_ECB(key, profile))


# print(key.hex())
# input_string = 'foo=bar&baz=qux&zap=zazzle'
#
# parsing = parsing_routine(input_string)
# # print(json.dumps(parsing, indent=4))

# input_string = b"foo@bar.com"
#
# profile = profile_for(input_string, key)
# print(profile, len(profile))
# print([profile[i:i + blocksize] for i in range(0, len(profile), blocksize)])


def get_blocksize():
    """ get the blocksize via padding"""
    add = len('email=')
    blocksize = 2
    cipher_chunks = [0, 1, 2]
    while cipher_chunks[1] != cipher_chunks[2]:
        blocksize += 1
        padding = b'A' * (blocksize - add) + b'A' * (blocksize * 2)
        ciphertext = profile_for(padding)
        cipher_chunks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    return blocksize


def forge_admin_cipherblock(blocksize):
    """fill first block to generate the cipherblock admin + pkcs#7"""
    add = len('email=')
    filler = b'A' * (blocksize - add)
    input_bytes = filler + pkcs7(b'admin')
    ciphertext = profile_for(input_bytes)
    cipher_chunks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    return cipher_chunks[1]


def forge_ciphertext(forge_block, blocksize):
    """first padding then replace the cipherblock user + pcks#7 by forge block"""
    forge_cipher = b''
    radical = len('email=&uid=10&role=')
    filler = b'a' * (blocksize - radical % blocksize - len(b'@bar.com')) + b'@bar.com'
    input_bytes = filler
    ciphertext = profile_for(input_bytes)
    cipher_chunks = [ciphertext[i:i + blocksize] for i in range(0, len(ciphertext), blocksize)]
    cipher_chunks[-1] = forge_block
    for block in cipher_chunks:
        forge_cipher += block
    return forge_cipher


# blocksize = get_blocksize()
# print(blocksize)
# forge_block = forge_admin_cipherblock(blocksize)
# print(forge_block)
# forge_cipher = forge_ciphertext(forge_block, blocksize)
# print(forge_cipher)
# cookie = decrypt_profile(forge_cipher)
# print(deparsing_routine(cookie))


class Oracle():
    def __init__(self):
        self.blocksize = 16
        self.radical = os.urandom(random.randint(0, 10))
        self.key = os.urandom(self.blocksize)

    def encrypt(self, plaintext):
        return AES_encrypt_ECB(self.key, self.radical + plaintext + base64.b64decode('''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK'''))


def attack_on_ECB_harder():
    oracle = Oracle()
    blocksize = 16

    radicalsize = 0
    while oracle.encrypt(b'A' * radicalsize)[:blocksize] != oracle.encrypt(b'A' * (radicalsize + 1))[:blocksize]:
        radicalsize += 1
    #radicalsize = (blocksize - radicalsize) % blocksize

    working_block_number = len(oracle.encrypt(b'A'*radicalsize))

    guess_chars = b''
    for working_block in range(1, working_block_number):
        padding = b'A' * (radicalsize + blocksize - 1)
        for j in range(blocksize):
            attack_dict = dict()
            append_padding = padding[j:]
            for i in range(2 ** 8):
                current_append_padding = append_padding + guess_chars + bytes([i])
                cipherblock_i = oracle.encrypt(current_append_padding)[
                                working_block * blocksize:blocksize * (1 + working_block)]
                attack_dict[cipherblock_i] = bytes([i])
            cible_cipherblok = oracle.encrypt(append_padding)[
                               working_block * blocksize:blocksize * (1 + working_block)]
            guess_char = attack_dict.get(cible_cipherblok, None)
            if guess_char is None:
                return guess_chars
            guess_chars += guess_char
    return guess_chars

# guess_chars = attack_on_ECB_harder()
# print(guess_chars.decode())


class Oracle_CBC():
    def __init__(self):
        self.blocksize = 16
        self.key = os.urandom(self.blocksize)
        self.iv = bytes(16)

    def encrypt(self, plaintext):
        return AES_encrypt_CBC(self.key, plaintext + base64.b64decode('''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK'''))


def attack_on_CBC():
    oracle_cbc = Oracle_CBC()
    working_block_number = len(append_oracle(key, b''))

    blocksize = 16

    guess_char = b''  # delete
    guess_chars = b''
    for working_block in range(working_block_number):
        padding = b'A' * (blocksize - 1)
        for j in range(blocksize):
            attack_dict = dict()
            append_padding = padding[j:]
            for i in range(2 ** 8):
                current_append_padding = append_padding + guess_chars + bytes([i])
                cipherblock_i = oracle_cbc.encrypt(current_append_padding)[
                                working_block * blocksize:blocksize * (1 + working_block)]
                attack_dict[cipherblock_i] = bytes([i])

            cible_cipherblok = oracle_cbc.encrypt(append_padding)[
                               working_block * blocksize:blocksize * (1 + working_block)]
            guess_char = attack_dict.get(cible_cipherblok, None)
            if guess_char is None:
                return guess_chars
            guess_chars += guess_char
        # message = xor(guess_chars, last_cipherblock)

        # print(guess_char.decode(), end = '')

    return guess_chars

guess_chars = attack_on_CBC()
