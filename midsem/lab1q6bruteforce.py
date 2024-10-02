import string
from math import gcd

# Alphabet setup
alphabet = string.ascii_uppercase
letter_to_num = {letter: idx for idx, letter in enumerate(alphabet)}
num_to_letter = {idx: letter for idx, letter in enumerate(alphabet)}


# Function to calculate modular inverse of 'a' mod 26
def mod_inverse(a, m=26):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


# Affine cipher decryption function
def affine_decrypt(ciphertext, a, b):
    plaintext = ""
    a_inv = mod_inverse(a)
    if a_inv is None:
        return None  # a does not have a modular inverse

    for char in ciphertext:
        if char in letter_to_num:
            y = letter_to_num[char]
            x = (a_inv * (y - b)) % 26
            plaintext += num_to_letter[x]
        else:
            plaintext += char  # Handle non-alphabet characters (if any)

    return plaintext


# Known values
ciphertext = "GL"
known_plaintext = "ab"

# Try all possible combinations of 'a' and 'b'
for a in range(1, 26):
    if gcd(a, 26) == 1:  # 'a' must be coprime with 26
        for b in range(26):
            decrypted_message = affine_decrypt(ciphertext, a, b)
            if decrypted_message == known_plaintext.upper():
                print(f"Found key: a = {a}, b = {b}")
                print(f"Decrypted message: {decrypted_message}")
