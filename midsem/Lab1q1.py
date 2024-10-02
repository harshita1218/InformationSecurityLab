# Function to encrypt using Additive cipher
#Q1) Encrypt the message "I am learning information security" using each of the following ciphers.
#Ignore the space between words. Decrypt the message to get the original plaintext: a) Additive
#cipher with key = 20 b) Multiplicative cipher with key = 15 c) Affine cipher with key = (15, 20)
def encrypt_additive(plaintext, key):
    encrypted = ''
    for char in plaintext:
        if char.isalpha():
            encrypted += chr(((ord(char.upper()) - 65 + key) % 26) + 65)
    return encrypted


# Function to decrypt using Additive cipher
def decrypt_additive(ciphertext, key):
    decrypted = ''
    for char in ciphertext:
        decrypted += chr(((ord(char) - 65 - key) % 26) + 65)
    return decrypted


# Function to encrypt using Multiplicative cipher
def encrypt_multiplicative(plaintext, key):
    encrypted = ''
    for char in plaintext:
        if char.isalpha():
            encrypted += chr(((ord(char.upper()) - 65) * key % 26) + 65)
    return encrypted


# Function to decrypt using Multiplicative cipher
def decrypt_multiplicative(ciphertext, key):
    decrypted = ''
    inverse_key = pow(key, -1, 26)  # Multiplicative inverse modulo 26
    for char in ciphertext:
        decrypted += chr(((ord(char) - 65) * inverse_key % 26) + 65)
    return decrypted


# Function to encrypt using Affine cipher
def encrypt_affine(plaintext, key1, key2):
    encrypted = ''
    for char in plaintext:
        if char.isalpha():
            encrypted += chr(((ord(char.upper()) - 65) * key1 + key2) % 26 + 65)
    return encrypted


# Function to decrypt using Affine cipher
def decrypt_affine(ciphertext, key1, key2):
    decrypted = ''
    inverse_key1 = pow(key1, -1, 26)  # Multiplicative inverse modulo 26
    for char in ciphertext:
        decrypted += chr((inverse_key1 * (ord(char) - 65 - key2) % 26) + 65)
    return decrypted


# Main code to test the ciphers
message = "I am learning information security".replace(" ", "").upper()
additive_key = 20
multiplicative_key = 15
affine_key1, affine_key2 = 15, 20

encrypted_additive = encrypt_additive(message, additive_key)
decrypted_additive = decrypt_additive(encrypted_additive, additive_key)

encrypted_multiplicative = encrypt_multiplicative(message, multiplicative_key)
decrypted_multiplicative = decrypt_multiplicative(encrypted_multiplicative, multiplicative_key)

encrypted_affine = encrypt_affine(message, affine_key1, affine_key2)
decrypted_affine = decrypt_affine(encrypted_affine, affine_key1, affine_key2)

# Display results
print("Original message:", message)
print("\nAdditive Cipher:")
print("Encrypted:", encrypted_additive)
print("Decrypted:", decrypted_additive)

print("\nMultiplicative Cipher:")
print("Encrypted:", encrypted_multiplicative)
print("Decrypted:", decrypted_multiplicative)

print("\nAffine Cipher:")
print("Encrypted:", encrypted_affine)
print("Decrypted:", decrypted_affine)
