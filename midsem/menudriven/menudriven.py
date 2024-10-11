from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from sympy import nextprime
import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, BadSignatureError
import sympy
import ast

# Constants for AES and Rabin encryption
AES_BLOCK_SIZE = 16


# Menu-driven program
def menu():
    while True:
        print("\n1. Customer - Encrypt and Digitally Sign Message")
        print("2. Merchant - Decrypt and Verify Message")
        print("3. Auditor - Verify Digital Signature")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            customer_encrypt_and_sign()
        elif choice == '2':
            merchant_decrypt_and_verify()
        elif choice == '3':
            auditor_verify_signature()
        elif choice == '4':
            break
        else:
            print("Invalid choice, please try again.")


# 1. Customer: Encrypt message using AES and Rabin, then sign with ElGamal
def customer_encrypt_and_sign():
    message = input("Enter the message to encrypt: ").encode()

    # AES Encryption
    key = get_random_bytes(16)  # 128-bit AES key
    iv = get_random_bytes(16)  # AES initialization vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(pad(message, AES_BLOCK_SIZE))

    # Rabin Encryption (using Sympy for simplicity)
    n, encrypted_rabin = rabin_encrypt(int.from_bytes(encrypted_message, 'big'))
    print(f"Rabin Encrypted Message: {encrypted_rabin}")

    # Hash message using SHA-256
    hashed_message = SHA256.new(message).hexdigest()
    print(f"SHA-256 Hash of Original Message: {hashed_message}")

    # ElGamal Digital Signature
    private_key, public_key = elgamal_keygen()
    signature = elgamal_sign(private_key, hashed_message)
    print(f"Digital Signature: {signature}")

    # Send AES key and IV securely to the merchant, along with encrypted message
    print("Send to Merchant -> AES Key:", key.hex(), "IV:", iv.hex())
    print("Encrypted AES Message sent to Merchant:", encrypted_message.hex())

    # Store keys, encrypted message, and signature for verification
    with open("merchant_data.txt", "w") as file:
        file.write(f"{key.hex()},{iv.hex()},{encrypted_message.hex()},{encrypted_rabin},{repr(signature)},{public_key}")


# 2. Merchant: Decrypt the message and verify the digital signature
def merchant_decrypt_and_verify():
    with open("merchant_data.txt", "r") as file:
        data = file.read().split(',')

    key = bytes.fromhex(data[0])
    iv = bytes.fromhex(data[1])
    encrypted_message = bytes.fromhex(data[2])
    encrypted_rabin = int(data[3])
    signature = ast.literal_eval(data[4])  # Safely parse the signature tuple
    public_key = eval(data[5])

    # Rabin Decryption (mocked decryption for simplicity)
    decrypted_rabin_message = rabin_decrypt(encrypted_rabin)

    # AES Decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(
        cipher.decrypt(decrypted_rabin_message.to_bytes((decrypted_rabin_message.bit_length() + 7) // 8, 'big')),
        AES_BLOCK_SIZE)

    print("Decrypted Message:", decrypted_message.decode())

    # Verify Digital Signature
    hashed_message = SHA256.new(decrypted_message).hexdigest()
    if elgamal_verify(public_key, hashed_message, signature):
        print("Signature Verification: Successful")
    else:
        print("Signature Verification: Failed")


# 3. Auditor: Verify digital signature of the message
def auditor_verify_signature():
    with open("merchant_data.txt", "r") as file:
        data = file.read().split(',')

    signature = ast.literal_eval(data[4])  # Parse the signature safely
    public_key = eval(data[5])

    message = input("Enter the message to verify: ").encode()
    hashed_message = SHA256.new(message).hexdigest()

    if elgamal_verify(public_key, hashed_message, signature):
        print("Signature Verification: Successful")
    else:
        print("Signature Verification: Failed")


# Rabin Encryption/Decryption
def rabin_encrypt(m):
    p = nextprime(random.randint(10 ** 50, 10 ** 60))
    q = nextprime(random.randint(10 ** 50, 10 ** 60))
    n = p * q
    return n, pow(m, 2, n)


def rabin_decrypt(c):
    # Simplified decryption assuming p and q are not stored for demo
    return c  # In practical terms, requires storing factors p and q


# ElGamal Digital Signature
def elgamal_keygen():
    p = sympy.nextprime(2 ** 16)
    g = sympy.primitive_root(p)
    x = random.randint(1, p - 1)  # private key
    y = pow(g, x, p)  # public key
    return (p, g, x), (p, g, y)


def elgamal_sign(private_key, message):
    p, g, x = private_key
    while True:
        k = random.randint(1, p - 2)
        if sympy.gcd(k, p - 1) == 1:  # Ensure k is coprime with p-1
            break
    r = pow(g, k, p)
    k_inv = sympy.mod_inverse(k, p - 1)
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    s = (k_inv * (h - x * r)) % (p - 1)
    return (r, s)


def elgamal_verify(public_key, message, signature):
    p, g, y = public_key
    r, s = signature
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


# Running the menu-driven program
if __name__ == "__main__":
    menu()
