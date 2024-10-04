# Suppose that XYZ Logistics has decided to use the RSA cryptosystem to secure their sensitive 
# communications. However, the security team at XYZ Logistics has discovered that one of their 
# employees,  Eve,  has  obtained  a  partial  copy  of  the  RSA  private  key  and  is  attempting  to 
# recover the full private key to decrypt the company's communications. 
# Eve's attack involves exploiting a vulnerability in the RSA key generation process, where the 
# prime factors (p and q) used to generate the modulus (n) are not sufficiently large or random. 
#  Develop a Python script that can demonstrate the attack on the vulnerable RSA cryptosystem  
# and discuss the steps to mitigate the attack.


from Crypto.Util.number import getPrime, inverse
import math

# RSA key generation with small, vulnerable primes
def generate_weak_rsa_keypair(bits=32):
    p = getPrime(bits)  # Generate small prime p
    q = getPrime(bits)  # Generate small prime q
    n = p * q  # Compute modulus n
    phi = (p - 1) * (q - 1)  # Euler's totient function phi(n)
    e = 65537  # Common public exponent
    d = inverse(e, phi)  # Compute the private key (modular inverse of e modulo phi)
    public_key = (n, e)
    private_key = (d, p, q)
    return public_key, private_key

# Eve's attack: Factorize n into p and q
def factorize_n(n):
    for i in range(2, int(math.isqrt(n)) + 1):  # Trial division up to sqrt(n)
        if n % i == 0:
            return i, n // i  # Return p and q once factors are found
    return None, None

# Function to compute the private key given p and q
def recover_private_key(p, q, e):
    phi = (p - 1) * (q - 1)  # Compute phi(n)
    d = inverse(e, phi)  # Compute private key d
    return d

# Example: Generate weak RSA keys
public_key, private_key = generate_weak_rsa_keypair()
n, e = public_key
d, p, q = private_key

print(f"Weak Public Key: n = {n}, e = {e}")
print(f"Weak Private Key: d = {d}, p = {p}, q = {q}")

# Eve's attack: Factor the weak modulus n
factored_p, factored_q = factorize_n(n)
print(f"Factored primes: p = {factored_p}, q = {factored_q}")

# Recover the private key using the factored primes
recovered_d = recover_private_key(factored_p, factored_q, e)
print(f"Recovered Private Key: d = {recovered_d}")

# Compare with the original private key
if recovered_d == d:
    print("Private key successfully recovered by Eve!")
else:
    print("Failed to recover the private key.")
