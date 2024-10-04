def vigenere_encrypt(plaintext, keyword):
    ciphertext = ""
    keyword_repeated = ""
    keyword = keyword.upper()
    
    # Repeat the keyword to match the length of the plaintext, ignoring spaces
    keyword_repeated = (keyword * ((len(plaintext) // len(keyword)) + 1))[:len(plaintext)]

    # Encrypt the plaintext using the Vigenère cipher
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            p = ord(plaintext[i].upper()) - ord('A')  # Position of plaintext letter
            k = ord(keyword_repeated[i]) - ord('A')  # Position of keyword letter
            c = (p + k) % 26  # Vigenère cipher encryption formula
            ciphertext += chr(c + ord('A'))  # Convert back to letter
        else:
            ciphertext += plaintext[i]  # Non-alphabetic characters are added as-is
    return ciphertext

# Given data
plaintext = "Life is full of surprises"
keyword = "HEALTH"

# Encrypt the message using Vigenère cipher
ciphertext = vigenere_encrypt(plaintext, keyword)
print("Ciphertext:", ciphertext)
