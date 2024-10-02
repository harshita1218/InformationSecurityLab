def int_to_bytes(x):
    """Convert an integer to bytes."""
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bytes_to_int(b):
    """Convert bytes to an integer."""
    return int.from_bytes(b, byteorder='big')

def encrypt_rsa(message, n, e):
    """Encrypt the message using RSA."""
    message_int = bytes_to_int(message.encode('utf-8'))  # Convert message to integer
    ciphertext_int = pow(message_int, e, n)  # RSA encryption
    return ciphertext_int

def decrypt_rsa(ciphertext_int, n, d):
    """Decrypt the ciphertext using RSA."""
    decrypted_int = pow(ciphertext_int, d, n)  # RSA decryption
    decrypted_message = int_to_bytes(decrypted_int).decode('utf-8', errors='ignore')  # Convert integer back to string
    return decrypted_message

def main():
    # RSA public key
    n = 323
    e = 5

    # RSA private key
    d = 173

    # Message to encrypt
    message = "Cryptographic Protocols"

    # Encrypt the message
    ciphertext = encrypt_rsa(message, n, e)
    print(f"Ciphertext (integer): {ciphertext}")

    # Decrypt the ciphertext
    decrypted_message = decrypt_rsa(ciphertext, n, d)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()
