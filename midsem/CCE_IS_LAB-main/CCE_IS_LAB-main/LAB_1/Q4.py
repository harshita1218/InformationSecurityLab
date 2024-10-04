import numpy as np


def mod_inv(a, m):
    # Calculate the modular inverse of a under modulo m
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"No modular inverse for {a} under modulo {m}")

def modular_matrix_inverse(matrix, mod):
    # Calculate the modular inverse of a matrix under modulo 26
    det = int(np.round(np.linalg.det(matrix)))  # Determinant
    det_inv = mod_inv(det, mod)  # Modular inverse of the determinant
    
    # Calculate the adjugate (cofactor matrix transpose)
    matrix_inv = np.round(det_inv * np.linalg.inv(matrix) * det).astype(int) % mod
    
    return matrix_inv

def encrypt_hill(message, key):
    message = message.replace(" ", "").casefold()
    n = key.shape[0]
    
    # Padding
    while len(message) % n != 0:
        message += 'x'  
    
    # Convert message to numerical matrix
    matrix = [ord(ch) - ord('a') for ch in message]
    matrix = np.array(matrix).reshape(-1, n).T
    
    # Encrypt the message
    encrypted_message_array = np.dot(key, matrix) % 26
    
    # Convert back to characters
    encrypted_message = ''.join(chr(num + ord('a')) for num in encrypted_message_array.T.flatten())
    
    return encrypted_message

def decrypt_hill(encrypted_message, key):
    encrypted_message = encrypted_message.replace(" ", "").casefold()
    n = key.shape[0]
    
    # Convert encrypted message to numerical matrix
    matrix = [ord(ch) - ord('a') for ch in encrypted_message]
    matrix = np.array(matrix).reshape(-1, n)
    
    # Compute the modular inverse of the key matrix
    key_inv = modular_matrix_inverse(key, 26)
    
    # Decrypt the message
    decrypted_message_array = np.dot(matrix, key_inv) % 26
    
    # Convert back to characters
    decrypted_message = ''.join(chr(num + ord('a')) for num in decrypted_message_array.flatten())
    
    return decrypted_message

# Example usage
key_matrix = np.array([[3, 3], [2, 7]])  
message = "We live in an insecure world"
encrypted_message = encrypt_hill(message, key_matrix)
print("Encrypted message:", encrypted_message)
