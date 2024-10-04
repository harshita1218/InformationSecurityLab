# DigiRights Inc. is a leading provider of digital content, including e-books, movies, and music. 
# The company has implemented a secure digital rights management (DRM) system using the 
# ElGamal  cryptosystem  to  protect  its  valuable  digital  assets.  Implement  a  Python-based 
# centralized key management and access control service that can: 
# • Key Generation: Generate a master public-private key pair using the ElGamal 
# cryptosystem. The key size should be configurable (e.g., 2048 bits). 
# • Content Encryption: Provide an API for content creators to upload their digital content and 
# have it encrypted using the master public key. 
# • Key  Distribution:  Manage  the  distribution  of  the  master  private  key  to  authorized 
# customers, allowing them to decrypt the content. 
# • Access Control: Implement flexible access control mechanisms, such as: 
# o Granting limited-time access to customers for specific content 
# o Revoking access to customers for specific content 
# o Allowing content creators to manage access to their own content 
# • Key Revocation: Implement a process to revoke the master private key in case of a security 
# breach or other emergency. 
# Database and Domain Name Servers (DNS) 
# • Key Renewal: Automatically renew the master public-private key pair at regular intervals 
# (e.g., every 24 months) to maintain the security of the DRM system. 
# • Secure Storage: Securely store the master private key, ensuring that it is not accessible to 
# unauthorized parties. 
# • Auditing and Logging: Maintain detailed logs of all key management and access control 
# operations to enable auditing and troubleshooting.

import os
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Random import random

# Function to generate the master public-private key pair using ElGamal
def generate_elgamal_keypair(bits=2048):
    p = getPrime(bits)  # Generate a large prime
    g = random.randint(2, p-1)  # Random generator g
    x = random.randint(2, p-2)  # Private key (random x)
    h = pow(g, x, p)  # Public key component h = g^x mod p
    public_key = (p, g, h)
    private_key = x
    return public_key, private_key

# Example: Generate 2048-bit master key pair
public_key, private_key = generate_elgamal_keypair(2048)
print("Master Public Key:", public_key)
print("Master Private Key:", private_key)

# Function to encrypt content using ElGamal public key
def elgamal_encrypt(public_key, content):
    p, g, h = public_key
    k = random.randint(2, p-2)  # Random session key
    c1 = pow(g, k, p)  # Compute c1 = g^k mod p
    m = bytes_to_long(content.encode())  # Convert content to long integer
    c2 = (m * pow(h, k, p)) % p  # Compute c2 = m * h^k mod p
    return c1, c2

# Example: Encrypt digital content
content = "This is a valuable e-book."
ciphertext = elgamal_encrypt(public_key, content)
print("Encrypted Content:", ciphertext)

# Function to securely deliver the private key to authorized users
def distribute_private_key_to_customer(customer_id, private_key):
    # In real use, this would be done over an encrypted channel (TLS)
    print(f"Distributing private key to customer {customer_id}...")

# Example: Distribute the private key
distribute_private_key_to_customer("Customer123", private_key)

import time

# In-memory store for access control records
access_control = {}

# Function to grant access to content for a customer
def grant_access(customer_id, content_id, access_duration_sec):
    expiry_time = time.time() + access_duration_sec
    access_control[customer_id] = {'content_id': content_id, 'expires': expiry_time}
    print(f"Granted access to {content_id} for customer {customer_id} until {time.ctime(expiry_time)}.")

# Function to revoke access
def revoke_access(customer_id, content_id):
    if customer_id in access_control and access_control[customer_id]['content_id'] == content_id:
        del access_control[customer_id]
        print(f"Access to {content_id} revoked for customer {customer_id}.")
    else:
        print(f"Customer {customer_id} does not have access to {content_id}.")

# Function to check access
def check_access(customer_id, content_id):
    if customer_id in access_control and access_control[customer_id]['content_id'] == content_id:
        if time.time() < access_control[customer_id]['expires']:
            print(f"Access granted to {content_id} for customer {customer_id}.")
            return True
        else:
            print(f"Access expired for customer {customer_id}.")
    print(f"Access denied to {content_id} for customer {customer_id}.")
    return False

# Example: Grant access to content for 60 seconds
grant_access("Customer123", "ContentXYZ", 60)

# Check access
check_access("Customer123", "ContentXYZ")


# Function to revoke the master private key
def revoke_master_key():
    global private_key
    print("Revoking master private key due to security breach...")
    private_key = None  # Simulate revocation by nullifying the key
    print("Master private key revoked.")

# Function to renew the master public-private key pair
def renew_master_key():
    global public_key, private_key
    print("Renewing master public-private key pair...")
    public_key, private_key = generate_elgamal_keypair(2048)
    print("New master public-private key pair generated.")

# Example: Revoke and renew the master key
revoke_master_key()
renew_master_key()

import logging

# Configure logging to a file
logging.basicConfig(filename='drm_audit.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to log actions
def log_action(action):
    logging.info(action)

# Example: Log key generation and access control actions
log_action("Generated new master public-private key pair.")
log_action("Granted access to Customer123 for ContentXYZ.")
log_action("Revoked access to Customer123 for ContentXYZ.")