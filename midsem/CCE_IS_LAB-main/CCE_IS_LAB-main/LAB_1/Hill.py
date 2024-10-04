import numpy as np
import string


def hill_cipher_encrypt(message, key_matrix):
    # Remove spaces and convert to lowercase
    message = message.replace(" ", "").lower()

    # Check if the message length is odd, pad with 'x' if necessary
    if len(message) % 2 != 0:
        message += "x"

    # Convert letters to numbers (a=0, b=1, ..., z=25)
    alphabet = string.ascii_lowercase
    message_numbers = [alphabet.index(letter) for letter in message]

    # Reshape the message numbers into a matrix with 2 rows
    message_matrix = np.reshape(message_numbers, (2,-1))

    #print(message_matrix)

    # Perform matrix multiplication and mod 26
    cipher_matrix = np.dot(key_matrix, message_matrix) % 26



    # Convert numbers back to letters
    cipher_text = "".join(alphabet[num] for num in cipher_matrix.T.flatten())

    return cipher_text

def hill_cipher_decrypt(message, key_matrix):
    # Compute the modular inverse of the key matrix
    key_inv = np.linalg.inv(key_matrix) % 26
    # Compute the determinant of the key matrix
    det = np.linalg.det(key_matrix) % 26

    key_inv = key_inv*det*pow(det,-1,26) %26

    alphabet = string.ascii_lowercase
    message_numbers = [alphabet.index(letter) for letter in message]

    message_matrix = np.reshape(message_numbers, (2,-1))

    # Compute the decrypted message matrix
    decrypted_matrix = np.dot(key_inv,message_matrix) % 26

    # Convert the decrypted matrix back to a list of numbers
    decrypted_numbers = decrypted_matrix.T.flatten().tolist()

    # Convert the numbers back to letters
    decrypted_text = "".join(string.ascii_lowercase[num] for num in decrypted_numbers)

    return decrypted_text


# Key matrix
key_matrix = np.array([[3, 3], [2, 7]])

# Message to encrypt
message = "We live in an insecure world"

# Encrypt the message
encrypted_message = hill_cipher_encrypt(message, key_matrix)

print("Original message:", message)
print("Encrypted message:", encrypted_message)

decrypted_message = hill_cipher_decrypt(encrypted_message, key_matrix)

print("Decrypted message:", decrypted_message)
