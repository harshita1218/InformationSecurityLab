def byte_to_int(byte):
    """Convert a single byte to an integer."""
    return int.from_bytes(byte, 'big')

def int_to_byte(integer):
    """Convert an integer back to a single byte."""
    return integer.to_bytes(1, 'big')

# Given RSA parameters
n = 323  # Modulus
e = 5    # Public exponent
d = 173  # Private exponent

# Original message
message = "Cryptographic Protocols"
print(f"Original Message: {message}")

# Step 1: Encrypt each byte of the message
ciphertext = []
for byte in message.encode('utf-8'):
    # Encrypt the byte
    encrypted_byte = pow(byte_to_int(bytes([byte])), e, n)
    ciphertext.append(encrypted_byte)

print(f"Ciphertext (byte by byte): {ciphertext}")

# Step 2: Decrypt each byte of the ciphertext
decrypted_message = []
for encrypted_byte in ciphertext:
    # Decrypt the byte
    decrypted_byte = pow(encrypted_byte, d, n)
    decrypted_message.append(int_to_byte(decrypted_byte))

# Convert the decrypted bytes back to a string
decrypted_message = b''.join(decrypted_message).decode('utf-8', errors='ignore')
print(f"Decrypted Message: {decrypted_message}")
