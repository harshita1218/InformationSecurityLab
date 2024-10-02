from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# --- Generate RSA Keys for Alice ---
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --- Sign Document with RSA Private Key ---
def sign_document(private_key, document):
    signature = private_key.sign(
        document,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# --- Verify Digital Signature with RSA Public Key ---
def verify_signature(public_key, document, signature):
    try:
        public_key.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# --- Serialize Keys for Exchange ---
def serialize_key(key, private=False):
    if private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

# --- Load Serialized Keys ---
def load_private_key(serialized_key):
    return serialization.load_pem_private_key(serialized_key, password=None)

def load_public_key(serialized_key):
    return serialization.load_pem_public_key(serialized_key)

# --- Simulation of Alice and Bob ---
def alice_bob_demo():
    # Alice's RSA Key Pair
    alice_private_key, alice_public_key = generate_rsa_keys()

    # Bob's RSA Key Pair
    bob_private_key, bob_public_key = generate_rsa_keys()

    # Document to be signed (message)
    document = b"This is a legal document."

    # Alice signs the document
    print("Alice signs the document...")
    alice_signature = sign_document(alice_private_key, document)

    # Bob receives the document and verifies Alice's signature
    print("Bob verifies Alice's signature...")
    is_valid = verify_signature(alice_public_key, document, alice_signature)
    if is_valid:
        print("Alice's signature is valid.")
    else:
        print("Alice's signature is NOT valid.")

    # Bob now signs his own document
    print("\nBob signs the document...")
    bob_signature = sign_document(bob_private_key, document)

    # Alice receives the document and verifies Bob's signature
    print("Alice verifies Bob's signature...")
    is_valid_bob = verify_signature(bob_public_key, document, bob_signature)
    if is_valid_bob:
        print("Bob's signature is valid.")
    else:
        print("Bob's signature is NOT valid.")

# Run the demo
alice_bob_demo()
