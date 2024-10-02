import string

# Alphabet setup
alphabet = string.ascii_lowercase

# Function to find the shift between two characters
def find_shift(ciphertext_char, plaintext_char):
    return (ord(ciphertext_char.lower()) - ord(plaintext_char.lower())) % 26

# Function to apply the shift to decrypt
def decrypt_shift_cipher(ciphertext, shift):
    decrypted_message = ""
    for char in ciphertext:
        if char.isalpha():
            decrypted_message += chr((ord(char.lower()) - ord('a') - shift) % 26 + ord('a'))
        else:
            decrypted_message += char
    return decrypted_message

# Given ciphertext and known plaintext
ciphertext_example = "CIW"
known_plaintext = "yes"

# Find the shift
shifts = [find_shift(c, p) for c, p in zip(ciphertext_example, known_plaintext)]
shift = shifts[0]  # Assuming the same shift for all characters

# Decrypt the new ciphertext
ciphertext_to_decrypt = "XVIEWYWI"
decrypted_message = decrypt_shift_cipher(ciphertext_to_decrypt, shift)

# Output the shift and the decrypted message
print(f"Detected Shift: {shift}")
print(f"Decrypted Message: {decrypted_message}")
