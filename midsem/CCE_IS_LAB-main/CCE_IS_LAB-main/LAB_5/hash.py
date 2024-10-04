# Implement the hash function in Python. Your function should start with an initial hash value of 5381 and for each character in the input string, multiply the current hash value by 33, add the ASCII value of the character, and use bitwise operations to ensure thorough mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range by applying an appropriate mask.

def hashing(message, hash_val=5381):
    for ch in message:
        # Multiply the current hash by 33 and add the ASCII value of the character
        hash_val = ((hash_val * 33) + ord(ch)) & 0xFFFFFFFF  # Keep within 32-bit range
    return hash_val

hashed = hashing("AnushriVirajSakhardande")
print(hashed)

