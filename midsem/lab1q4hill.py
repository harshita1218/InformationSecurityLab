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

# Hill cipher decryption function
def hill_cipher_decrypt(ciphertext, key_matrix):
    # Calculate the determinant of the key matrix
    det = int(np.round(np.linalg.det(key_matrix))) % 26

    # Calculate the modular inverse of the determinant
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    det_inv = mod_inverse(det, 26)

    # Calculate the inverse of the key matrix
    adjugate_matrix = np.array([[key_matrix[1, 1], -key_matrix[0, 1]],
                                [-key_matrix[1, 0], key_matrix[0, 0]]])
    key_matrix_inv = (det_inv * adjugate_matrix) % 26

    # Convert the ciphertext to numbers
    ciphertext_as_nums = [letter_to_num[letter] for letter in ciphertext]

    # Divide ciphertext into pairs for matrix multiplication
    decrypted_message = ""
    for i in range(0, len(ciphertext_as_nums), 2):
        # Take a pair of numbers from the ciphertext
        pair = np.array([[ciphertext_as_nums[i]], [ciphertext_as_nums[i + 1]]])

        # Multiply by the inverse key matrix and mod 26
        decrypted_pair = np.dot(key_matrix_inv, pair) % 26

        # Convert numbers back to letters
        decrypted_message += num_to_letter[int(decrypted_pair[0][0]) % 26]
        decrypted_message += num_to_letter[int(decrypted_pair[1][0]) % 26]

    return decrypted_message

# Define the key matrix
key_matrix = np.array([[3, 3], [2, 7]])

# Test the Hill Cipher
plaintext = "We live in an insecure world"

# Encrypt the message
encrypted_message = hill_cipher_encrypt(plaintext, key_matrix)
print("Encrypted Message:", encrypted_message)

# Decrypt the message
decrypted_message = hill_cipher_decrypt(encrypted_message, key_matrix)
print("Decrypted Message:", decrypted_message)
