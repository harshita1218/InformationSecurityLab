#  Encrypt the message "Classified Text" using Triple DES with the key 
# "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF". Then decrypt the ciphertext to 
# verify the original message. 

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Define the message
message = "Classified Text"

# Triple DES key (24 bytes / 48 hex characters)
key = get_random_bytes(24)

# Define the block size for DES3
block_size = DES3.block_size

def encrypt_3des(msg, key):
    try:
        # Generate a random IV for DES3
        iv = get_random_bytes(block_size)
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        padded_msg = pad(msg.encode('utf-8'), block_size)
        ciphertext = cipher.encrypt(padded_msg)
        return iv, ciphertext
    except Exception as e:
        return None, f"Encryption failed: {str(e)}"

def decrypt_3des(iv, ciphertext, key):
    try:
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, block_size).decode('utf-8')
        return plaintext
    except ValueError as e:
        return f"Decryption failed: {str(e)}"
    except Exception as e:
        return f"Decryption error: {str(e)}"

# Encrypt the message
iv, ciphertext = encrypt_3des(message, key)
if ciphertext:
    print(f'Ciphertext (hex): {ciphertext.hex()}')

    # Decrypt the ciphertext to verify the original message
    plaintext = decrypt_3des(iv, ciphertext, key)
    print(f'Plaintext: {plaintext}')
else:
    print(iv)  # Print the error message from encryption failure
