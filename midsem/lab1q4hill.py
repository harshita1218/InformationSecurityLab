import numpy as np
import string

# Alphabet setup
alphabet = string.ascii_lowercase
letter_to_num = {letter: idx for idx, letter in enumerate(alphabet)}
num_to_letter = {idx: letter for idx, letter in enumerate(alphabet)}


# Hill cipher encryption function
def hill_cipher_encrypt(plaintext, key_matrix):
    # Remove spaces and convert message to lowercase
    plaintext = plaintext.replace(" ", "").lower()

    # If the length of the plaintext is odd, pad with an extra 'x'
    if len(plaintext) % 2 != 0:
        plaintext += 'x'

    # Convert the plaintext to numbers
    plaintext_as_nums = [letter_to_num[letter] for letter in plaintext]

    # Divide plaintext into pairs for matrix multiplication
    encrypted_message = ""
    for i in range(0, len(plaintext_as_nums), 2):
        # Take a pair of numbers from the plaintext
        pair = np.array([[plaintext_as_nums[i]], [plaintext_as_nums[i + 1]]])

        # Multiply by the key matrix and mod 26
        encrypted_pair = np.dot(key_matrix, pair) % 26

        # Convert numbers back to letters
        encrypted_message += num_to_letter[encrypted_pair[0][0]]
        encrypted_message += num_to_letter[encrypted_pair[1][0]]

    return encrypted_message


# Define the key matrix
key_matrix = np.array([[3, 3], [2, 7]])

# Test the Hill Cipher
plaintext = "We live in an insecure world"

# Encrypt the message
encrypted_message = hill_cipher_encrypt(plaintext, key_matrix)

# Output the encrypted message
print("Encrypted Message:", encrypted_message)
