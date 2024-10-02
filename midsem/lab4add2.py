
import math
import sympy
from Crypto.Util.number import inverse

# Step 1: Generate a vulnerable RSA key pair with small primes p and q
def generate_weak_rsa_keys():
    # Vulnerable small primes p and q (for demonstration purposes)
    p = sympy.randprime(1000, 5000)
    q = sympy.randprime(1000, 5000)
    n = p * q
    e = 65537  # Commonly used public exponent

    # Compute the private exponent d using the modular inverse
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    # Public and private key
    public_key = (n, e)
    private_key = (n, d)
    print(f"Generated Weak RSA Keys:\np = {p}, q = {q}\nModulus (n) = {n}\n")
    return public_key, private_key, p, q

# Step 2: Eve's attack - factor n to find p and q
def factor_modulus(n):
    print(f"Attempting to factor n = {n}")
    # Using Fermat's factorization method for simplicity
    x = math.isqrt(n) + 1
    while True:
        y_squared = x* x - n
        y = math.isqrt(y_squared)
        if y * y == y_squared:
            break
        x += 1
    p = x - y
    q = x + y
    print(f"Successfully factored n into p = {p} and q = {q}")
    return p, q


# Step 3: Recover the private key and decrypt a message
def recover_private_key(n, e, p, q):
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return d


def encrypt_rsa(message, public_key):
    n, e = public_key
    message_int = int.from_bytes(message.encode(), 'big')
    ciphertext = pow(message_int, e, n)
    return ciphertext


def decrypt_rsa(ciphertext, private_key):
    n, d = private_key
    decrypted_int = pow(ciphertext, d, n)
    decrypted_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()
    return decrypted_message


def main():
    # Step 1: Generate weak RSA keys
    public_key, private_key, p, q = generate_weak_rsa_keys()

    # Step 2: Eve tries to factor the modulus n
    n, e = public_key
    p_eve, q_eve = factor_modulus(n)

    # Step 3: Eve recovers the private key
    d_eve = recover_private_key(n, e, p_eve, q_eve)
    private_key_eve = (n, d_eve)

    # Step 4: Demonstrate encryption and decryption
    message = "Sensitive Data"
    print(f"\nOriginal message: {message}")

    # Encrypt the message using the public key
    ciphertext = encrypt_rsa(message, public_key)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the message using the legitimate private key
    decrypted_message = decrypt_rsa(ciphertext, private_key)
    print(f"Decrypted message using legitimate private key: {decrypted_message}")

    # Decrypt the message using Eve's recovered private key
    decrypted_message_eve = decrypt_rsa(ciphertext, private_key_eve)
    print(f"Decrypted message using Eve's recovered private key: {decrypted_message_eve}")


if __name__ == "__main__":
    main()
