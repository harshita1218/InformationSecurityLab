from Crypto.PublicKey import RSA

# Generates a public/private key pair
def generate_keypair(nlength=1024):
    key = RSA.generate(nlength)
    pub_key = key.publickey()
    return pub_key, key

# Encrypts a message using the public key
def encrypt(pub_key, message):
    e = pub_key.e
    n = pub_key.n
    ciphertext = pow(message, e, n)
    return ciphertext

# Decrypts a ciphertext using the private key
def decrypt(priv_key, ciphertext):
    d = priv_key.d
    n = priv_key.n
    message = pow(ciphertext, d, n)
    return message


# Generate key pair
pub_key, priv_key = generate_keypair()

# Encrypt integers
a = 7
b = 3
ciphertext_a = encrypt(pub_key, a)
ciphertext_b = encrypt(pub_key, b)

# Perform multiplicative homomorphic operation (multiply ciphertexts)
ciphertext_product = (ciphertext_a * ciphertext_b) % pub_key.n

# Decrypt the result
decrypted_product = decrypt(priv_key, ciphertext_product)

# Print results
print(f"Ciphertext of a: {ciphertext_a}")
print(f"Ciphertext of b: {ciphertext_b}")
print(f"Ciphertext of a * b: {ciphertext_product}")
print(f"Decrypted product: {decrypted_product}")
print(f"Expected product: {a * b}")









































from Crypto.Util import number
import random

#Generates a public/private key pair for Paillier encryption
def generate_keypair(bits=512):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    g = n + 1  # g = n + 1 is often used in practical implementations
    lambda_n = (p - 1) * (q - 1)  # λ(n) = (p - 1)(q - 1)
    mu = number.inverse(lambda_n, n)  # Modular inverse of λ(n) modulo n
    return (n, g), (lambda_n, mu)

#Encrypts a message using the Paillier encryption scheme
def encrypt(public_key, message):
    n, g = public_key
    r = random.randint(1, n - 1)  # Random value for encryption
    ciphertext = (pow(g, message, n * n) * pow(r, n, n * n)) % (n * n)
    return ciphertext

#Decrypts a ciphertext using the Paillier encryption scheme
def decrypt(private_key, public_key, ciphertext):
    n, g = public_key
    lambda_n, mu = private_key
    u = pow(ciphertext, lambda_n, n * n)
    low = (u - 1) // n
    message = (low * mu) % n
    return message


# Generate key pair
public_key, private_key = generate_keypair(bits=512)

# Encrypt integers
a = 15
b = 25
ciphertext_a = encrypt(public_key, a)
ciphertext_b = encrypt(public_key, b)

# Perform additive homomorphic operation (add ciphertexts)
ciphertext_sum = (ciphertext_a * ciphertext_b) % (public_key[0] * public_key[0])

# Decrypt the result
decrypted_sum = decrypt(private_key, public_key, ciphertext_sum)

# Print results
print(f"Ciphertext of a: {ciphertext_a}")
print(f"Ciphertext of b: {ciphertext_b}")
print(f"Ciphertext of a + b: {ciphertext_sum}")
print(f"Decrypted sum: {decrypted_sum}")
print(f"Expected sum: {a + b}")
