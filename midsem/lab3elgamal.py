import random
from sympy import nextprime


# Helper function for modular exponentiation
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)


# Function to generate a random large prime
def generate_large_prime(bits=256):
    # Start with a random number and find the next prime
    random_number = random.getrandbits(bits)
    return nextprime(random_number)


# Function to generate ElGamal keys
def generate_keys():
    # Generate a large prime number p and a generator g
    p = generate_large_prime()
    g = random.randint(2, p - 2)  # g is typically a small number (generator of the group)

    # Private key (randomly chosen x such that 1 <= x <= p-2)
    x = random.randint(1, p - 2)

    # Public key (h = g^x mod p)
    h = mod_exp(g, x, p)

    return (p, g, h), x  # (public_key, private_key)


# Function to encrypt a message using ElGamal encryption
def encrypt(message, public_key):
    p, g, h = public_key

    # Convert message to an integer
    m = int.from_bytes(message.encode(), 'big')

    # Randomly choose an ephemeral key y (1 <= y <= p-2)
    y = random.randint(1, p - 2)

    # Compute c1 = g^y mod p
    c1 = mod_exp(g, y, p)

    # Compute c2 = m * h^y mod p
    c2 = (m * mod_exp(h, y, p)) % p

    return c1, c2  # Ciphertext (c1, c2)


# Function to decrypt the ciphertext using ElGamal decryption
def decrypt(ciphertext, private_key, p):
    c1, c2 = ciphertext
    x = private_key

    # Compute s = c1^x mod p
    s = mod_exp(c1, x, p)

    # Compute the inverse of s mod p
    s_inv = pow(s, -1, p)

    # Recover the original message: m = c2 * s_inv mod p
    m = (c2 * s_inv) % p

    # Convert the integer message back to a string
    decrypted_message = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

    return decrypted_message


# Example usage
if __name__ == "__main__":
    # Generate public and private keys
    public_key, private_key = generate_keys()

    # Original message
    message = "Confidential Data"

    # Encrypt the message
    ciphertext = encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_message = decrypt(ciphertext, private_key, public_key[0])
    print(f"Decrypted message: {decrypted_message}")

