import string

# Alphabet setup
alphabet = string.ascii_uppercase
letter_to_num = {letter: idx for idx, letter in enumerate(alphabet)}
num_to_letter = {idx: letter for idx, letter in enumerate(alphabet)}


# Function to encrypt using Vigenère cipher
def vigenere_encrypt(plaintext, keyword):
    # Prepare plaintext and keyword (remove spaces and convert to uppercase)
    plaintext = plaintext.replace(" ", "").upper()
    keyword = keyword.upper()

    ciphertext = ""
    keyword_length = len(keyword)

    # Loop through each character in the plaintext
    for i, char in enumerate(plaintext):
        if char in letter_to_num:
            # Get the corresponding shift from the keyword
            shift = letter_to_num[keyword[i % keyword_length]]
            # Encrypt the current character
            encrypted_char = (letter_to_num[char] + shift) % 26
            ciphertext += num_to_letter[encrypted_char]
        else:
            ciphertext += char  # Keep non-alphabetic characters unchanged

    return ciphertext


# Given plaintext and keyword
plaintext = "Life is full of surprises"
keyword = "HEALTH"

# Encrypt the message using Vigenère cipher
encrypted_message = vigenere_encrypt(plaintext, keyword)

# Output the encrypted message
print(f"Encrypted Message: {encrypted_message}")
