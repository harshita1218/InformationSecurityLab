import string

# Alphabet setup
alphabet = string.ascii_uppercase
letter_to_num = {letter: idx for idx, letter in enumerate(alphabet)}
num_to_letter = {idx: letter for idx, letter in enumerate(alphabet)}

# Function to decrypt an additive cipher with a given key
def additive_decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char in letter_to_num:
            y = letter_to_num[char]
            x = (y - key) % 26
            plaintext += num_to_letter[x]
        else:
            plaintext += char  # Keep non-alphabet characters as is (e.g., '/', '&')
    return plaintext

# Ciphertext given
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Trying different keys close to Alice's birthday (13)
for key in range(10, 17):
    decrypted_message = additive_decrypt(ciphertext, key)
    print(f"Key {key}: {decrypted_message}")
