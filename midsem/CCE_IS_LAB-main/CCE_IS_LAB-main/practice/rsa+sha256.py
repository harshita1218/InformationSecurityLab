from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Step 1: Generate RSA key pairs for the sender and recipient
recipient_key = RSA.generate(2048)  # Recipient's key
sender_key = RSA.generate(2048)     # Sender's key

recipient_public_key = recipient_key.publickey()
sender_public_key = sender_key.publickey()

# Example message
message = "Confidential: Please process this transaction by the end of the day."

# Step 2: Hash the message using SHA-256 for integrity
def hash_message(message):
    return SHA256.new(message.encode('utf-8'))

hashed_message = hash_message(message)
print(f"SHA-256 Hash: {hashed_message.hexdigest()}")

# Step 3: Sign the hash of the message using the sender's private key for authenticity
def sign_message(hashed_message, sender_private_key):
    signature = pkcs1_15.new(sender_private_key).sign(hashed_message)
    return signature

signature = sign_message(hashed_message, sender_key)
print(f"Digital Signature: {signature}")

# Step 4: Encrypt the message using RSA public key encryption (Recipient's public key) for confidentiality
def encrypt_message(message, recipient_public_key):
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
    return encrypted_message

encrypted_message = encrypt_message(message, recipient_public_key)
print(f"Encrypted Message: {encrypted_message}")

# Step 5: Decrypt the message using RSA private key (Recipient's private key)
def decrypt_message(encrypted_message, recipient_private_key):
    cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

decrypted_message = decrypt_message(encrypted_message, recipient_key)
print(f"Decrypted Message: {decrypted_message}")

# Step 6: Verify the digital signature using the sender's public key to ensure message integrity and authenticity
def verify_signature(hashed_message, signature, sender_public_key):
    try:
        pkcs1_15.new(sender_public_key).verify(hashed_message, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is invalid.")

# Verify the digital signature
verify_signature(hashed_message, signature, sender_public_key)
