import string

# Alphabet setup
alphabet = string.ascii_lowercase
letter_to_num = {letter: idx for idx, letter in enumerate(alphabet)}
num_to_letter = {idx: letter for idx, letter in enumerate(alphabet)}

# Vigenère cipher encryption and decryption functions
def vigenere_cipher_encrypt(plaintext, key):
    encrypted_message = ""
    key_length = len(key)
    key_as_int = [letter_to_num[letter] for letter in key]
    plaintext_as_int = [letter_to_num[letter] for letter in plaintext]

    for i in range(len(plaintext_as_int)):
        value = (plaintext_as_int[i] + key_as_int[i % key_length]) % 26
        encrypted_message += num_to_letter[value]

    return encrypted_message

def vigenere_cipher_decrypt(ciphertext, key):
    decrypted_message = ""
    key_length = len(key)
    key_as_int = [letter_to_num[letter] for letter in key]
    ciphertext_as_int = [letter_to_num[letter] for letter in ciphertext]

    for i in range(len(ciphertext_as_int)):
        value = (ciphertext_as_int[i] - key_as_int[i % key_length]) % 26
        decrypted_message += num_to_letter[value]

    return decrypted_message

# Test the Vigenère Cipher
plaintext = "thehouseisbeingsoldtonight".replace(" ", "").lower()
key_vigenere = "dollars"

encrypted_vigenere = vigenere_cipher_encrypt(plaintext, key_vigenere)
decrypted_vigenere = vigenere_cipher_decrypt(encrypted_vigenere, key_vigenere)

print("Vigenère Cipher:")
print(f"Encrypted: {encrypted_vigenere}")
print(f"Decrypted: {decrypted_vigenere}")
# Autokey cipher encryption and decryption functions
def autokey_cipher_encrypt(plaintext, key):
    encrypted_message = ""
    key_stream = [key] + [letter_to_num[letter] for letter in plaintext]
    plaintext_as_int = [letter_to_num[letter] for letter in plaintext]

    for i in range(len(plaintext_as_int)):
        value = (plaintext_as_int[i] + key_stream[i]) % 26
        encrypted_message += num_to_letter[value]

    return encrypted_message

def autokey_cipher_decrypt(ciphertext, key):
    decrypted_message = ""
    key_stream = [key]
    ciphertext_as_int = [letter_to_num[letter] for letter in ciphertext]

    for i in range(len(ciphertext_as_int)):
        value = (ciphertext_as_int[i] - key_stream[i]) % 26
        decrypted_letter = num_to_letter[value]
        decrypted_message += decrypted_letter
        key_stream.append(letter_to_num[decrypted_letter])

    return decrypted_message

# Test the Autokey Cipher
key_autokey = 7

encrypted_autokey = autokey_cipher_encrypt(plaintext, key_autokey)
decrypted_autokey = autokey_cipher_decrypt(encrypted_autokey, key_autokey)

print("\nAutokey Cipher:")
print(f"Encrypted: {encrypted_autokey}")
print(f"Decrypted: {decrypted_autokey}")
