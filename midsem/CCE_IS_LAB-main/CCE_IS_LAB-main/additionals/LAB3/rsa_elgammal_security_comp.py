## DOESN'T WORK



import time
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from Crypto.Random import get_random_bytes
from ecdsa import SigningKey, VerifyingKey, NIST256p  # Importing NIST256p for ECC
import secrets

# ElGamal functions
def elg_generate_keys(bits=256):
    # Generate ElGamal public and private keys
    p = secrets.randbits(bits)  # Randomly generate a prime
    g = secrets.randbelow(p - 1) + 1  # Random generator
    x = secrets.randbelow(p - 1) + 1  # Private key
    h = pow(g, x, p)  # Public key component
    return (p, g, h), x  # Public key (p, g, h) and private key x

def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    k = secrets.randbelow(p - 1) + 1  # Random integer for encryption
    c1 = pow(g, k, p)  # c1 = g^k mod p
    m = bytes_to_long(message)
    c2 = (m * pow(h, k, p)) % p  # c2 = m * h^k mod p
    return c1, c2

def elgamal_decrypt(private_key, public_key, c1, c2):
    p = public_key[0]
    x = private_key
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    return long_to_bytes(m)

# RSA functions
def rsa_generate_keys(bits=2048):
    key = RSA.generate(bits)
    return key.publickey(), key  # Returns public and private key

def rsa_encrypt(public_key, message):
    return public_key.encrypt(message, None)[0]

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(ciphertext)

# Testing function
def measure_performance(encryption_method, decryption_method, key_gen_method, message):
    # Measure key generation time
    start_time = time.time()
    public_key, private_key = key_gen_method()
    key_gen_time = time.time() - start_time

    # Measure encryption time
    start_time = time.time()
    ciphertext = encryption_method(public_key, message)
    encryption_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    decrypted_message = decryption_method(private_key, ciphertext)
    decryption_time = time.time() - start_time

    return key_gen_time, encryption_time, decryption_time, decrypted_message

# Main testing loop for performance comparison
sizes = [1024, 10240]  # 1 KB and 10 KB

for size in sizes:
    message = get_random_bytes(size)  # Generate random message of specified size

    # RSA performance measurement
    print(f"\nRSA Performance for message size: {size} bytes")
    rsa_key_gen_time, rsa_encryption_time, rsa_decryption_time, rsa_decrypted_message = measure_performance(
        rsa_generate_keys, rsa_encrypt, rsa_decrypt, message)
    print(f"Key Generation Time: {rsa_key_gen_time:.6f} seconds")
    print(f"Encryption Time: {rsa_encryption_time:.6f} seconds")
    print(f"Decryption Time: {rsa_decryption_time:.6f} seconds")
    print(f"Decrypted Message Matches: {message == rsa_decrypted_message}")

    # ElGamal performance measurement
    print(f"\nElGamal Performance for message size: {size} bytes")
    elgamal_key_gen_time, elgamal_encryption_time, elgamal_decryption_time, elgamal_decrypted_message = measure_performance(
        elg_generate_keys, elgamal_encrypt, elgamal_decrypt, message)
    print(f"Key Generation Time: {elgamal_key_gen_time:.6f} seconds")
    print(f"Encryption Time: {elgamal_encryption_time:.6f} seconds")
    print(f"Decryption Time: {elgamal_decryption_time:.6f} seconds")
    print(f"Decrypted Message Matches: {message == elgamal_decrypted_message}")

    # ECC performance measurement
    print(f"\nECC Performance for message size: {size} bytes")
    sk = SigningKey.generate(curve=NIST256p)  # Using NIST256p instead of SECP256r1
    vk = sk.get_verifying_key()

    # Measure ECC key generation time
    start_time = time.time()
    ecc_key_gen_time = time.time() - start_time

    # Measure ECC signing (equivalent to encryption) time
    start_time = time.time()
    ecc_signature = sk.sign(message)
    ecc_encryption_time = time.time() - start_time

    # Measure ECC verification (equivalent to decryption) time
    start_time = time.time()
    is_verified = vk.verify(ecc_signature, message)
    ecc_decryption_time = time.time() - start_time

    print(f"ECC Key Generation Time: {ecc_key_gen_time:.6f} seconds")
    print(f"ECC Signing Time: {ecc_encryption_time:.6f} seconds")
    print(f"ECC Verification Time: {ecc_decryption_time:.6f} seconds")
    print(f"Signature Verified: {is_verified}")

print("Performance evaluation complete.")
