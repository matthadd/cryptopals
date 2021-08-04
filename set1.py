# SET 1

# CHALLENGE 1

import base64

input_hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
exp_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


def hex_to_b64(input_hex):
    return base64.b64encode(input_bytes)


input_bytes = bytes.fromhex(input_hex)  # b"I'm killing your brain like a poisonous mushroom"
res = hex_to_b64(input_bytes)
# print(exp_output == res.decode())

# CHALLENGE 2

input_1 = '1c0111001f010100061a024b53535009181c'
input_2 = '686974207468652062756c6c277320657965'  # b"hit the bull's eye"
exp_output = ' 746865206b696420646f6e277420706c6179'  # b"the kid don't play"


def xor(input_bytes_1, input_bytes_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(input_bytes_1, input_bytes_2)])


input_bytes_1 = bytes.fromhex(input_1)
input_bytes_2 = bytes.fromhex(input_2)

res = xor(input_bytes_1, input_bytes_2)
# print(res.hex() == exp_output)

# CHALLENGE 3

cipher = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

cipher = bytes.fromhex(cipher)


def single_char_xor(input_bytes, char):
    return bytes([b1 ^ char for b1 in input_bytes])


def scoring(plaintext):
    frequency_english = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000}

    return sum([frequency_english.get(chr(i), 0) for i in plaintext.lower()])


def break_single_char_xor(cipher):
    possible_plaintext = []
    scores = []

    for i in range(2 ** 8):
        plaintext = single_char_xor(cipher, i)
        possible_plaintext.append(plaintext)
        scores.append(scoring(plaintext))

    guess_key = scores.index(max(scores))
    return guess_key


# guess_key = break_single_char_xor(cipher)
# print(chr(guess_key), single_char_xor(cipher, guess_key)) # 88 b"Cooking MC's like a pound of bacon"

# CHALLENGE 4
f = open('4.txt', 'r')
lines = []
scores = []
keys = []

for line in f:
    line = bytes.fromhex(line)
    possible_key = break_single_char_xor(line)
    plaintext = single_char_xor(line, possible_key)
    lines.append(plaintext)
    scores.append(scoring(plaintext))
    keys.append(possible_key)

index = scores.index(max(scores))
# print(chr(keys[index]), lines[index]) # 5 b'Now that the party is jumping\n'


# CHALLENGE 5

plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode()
key = 'ICE'.encode()


def repeating_xor(input_bytes, key):
    return bytes([input_bytes[i] ^ key[i % len(key)] for i in range(len(input_bytes))])


# cipher = repeating_xor(plaintext, key)
# print(cipher, type(cipher))
# plaintext = repeating_xor(cipher, key)
# print(plaintext.decode())

# CHALLENGE 6

input_bytes_1 = 'this is a test'.encode()
input_bytes_2 = 'wokka wokka!!!'.encode()


def hamming_distance(input_bytes_1, input_bytes_2):
    xor_bytes = xor(input_bytes_1, input_bytes_2)
    distance = 0
    for byte in xor_bytes:
        distance += sum([1 for bit in bin(byte) if bit == '1'])
    return distance


# distance = hamming_distance(input_bytes_1, input_bytes_2)
# print(distance) # 37

f = open('6.txt', 'r')
cipher = base64.b64decode(f.read())
f.close()


def break_repeating_xor(cipher):
    chunks = []
    res = []
    distances = {}

    for keysize in range(2, 41):
        chunks = [cipher[i:i + keysize] for i in range(0, len(cipher), keysize)]
        res = []
        for i in range(len(chunks) - 1):
            res.append(hamming_distance(chunks[i], chunks[i + 1]) / keysize)
        distances[keysize] = sum(res) / len(res)

    possible_key_length = sorted(distances.items(), key=lambda item: item[1])
    # print(possible_key_length[0])
    keysize = possible_key_length[0][0]

    key = b''
    block = []
    for i in range(keysize):
        block = []
        for j in range(i, len(cipher), keysize):
            block.append(cipher[j])
        guess_char = break_single_char_xor(block)
        key += bytes([guess_char])

    return key


# key = break_repeating_xor(cipher)
#
# plaintext = repeating_xor(cipher, key)
# print(key.decode())
# print()
# print(plaintext.decode())

# CHALLENGE 7

from Crypto.Cipher import AES

f = open('7.txt', 'r')
ciphertext = base64.b64decode(f.read())
f.close()

key = b"YELLOW SUBMARINE"


def AES_ECB(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


plaintext = AES_ECB(key, ciphertext[0:16])

# print(plaintext.decode())

# CHALLENGE 8

f = open('8.txt', 'r')
lines = []
for line in f:
    lines.append(bytes.fromhex(line))
f.close()

count = 0
block_size = 16
for line in lines:
    chunk = [line[i:i + block_size] for i in range(0, len(line), block_size)]
    for i in range(len(chunk)):
        for j in range(i, len(chunk)):
            if chunk[i] == chunk[j] and i is not j:
                guess = count
                # print(count, i, j, chunk[i], chunk[j])
    count += 1


# print(guess, lines[guess][0:16])

def replace(L, a, b):
    for i in range(len(L)):
        if L[i] == a:
            L[i] = b


def key_generator(L, lmin, lmax):
    """take key n-1 return key n"""
    if sum(L) == len(L) * lmax:
        return True

    L[-1] += 1
    for i in range(-1, -len(L) - 1, -1):
        if L[i] > lmax:
            L[i] = lmin
            L[i - 1] += 1


ciphertext = lines[guess]
plaintext = []
scores = []

start = 64  # 64 -> 32 to have space
end = 90
length = 16
L = [start] * length

# while key_generator(L, start, end) is not True:
#     replace(L, 64, 32)
#     key = bytes(L)
#     text = AES_ECB(key, ciphertext)
#     plaintext.append(text)
#     scores.append(scoring(text))
#     print(key, text)
#     print(scores.index(max(scores)))
#     replace(L, 32, 64)
