def caesar_decrypt(ciphertext, key):
    decrypted_message = ""
    for char in ciphertext:
        # Only decrypt alphabetic characters
        if char.isalpha():
            shift = ord('A') if char.isupper() else ord('a')
            decrypted_message += chr((ord(char) - shift - key) % 26 + shift)
        else:
            decrypted_message += char  # Keep non-alphabet characters unchanged
    return decrypted_message

# Encoded message
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Try all possible keys close to Alice's birthday (13th of the month)
for key in range(3, 24):  # ±10 around 13
    print(f"Trying key = {key}: {caesar_decrypt(ciphertext, key)}")
