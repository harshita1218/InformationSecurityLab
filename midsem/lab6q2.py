from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# --- Generate Diffie-Hellman Key Pair ---
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# --- Generate Shared Secret from Diffie-Hellman Exchange ---
def generate_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'diffie-hellman',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

# --- HMAC Signing ---
def create_hmac(key, message):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

# --- HMAC Verification ---
def verify_hmac(key, message, signature):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except:
        return False

# --- Diffie-Hellman Key Exchange and HMAC Example ---
def diffie_hellman_hmac_demo():
    # Step 1: Alice and Bob generate their DH parameters and key pairs
    parameters = generate_dh_parameters()

    # Alice's key pair
    alice_private_key, alice_public_key = generate_dh_keypair(parameters)

    # Bob's key pair
    bob_private_key, bob_public_key = generate_dh_keypair(parameters)

    # Step 2: Alice and Bob exchange public keys and compute the shared secret
    alice_shared_secret = generate_shared_secret(alice_private_key, bob_public_key)
    bob_shared_secret = generate_shared_secret(bob_private_key, alice_public_key)

    # Step 3: Verify that both shared secrets are the same
    assert alice_shared_secret == bob_shared_secret, "Shared secrets don't match!"

    print("Shared secret established successfully!")

    # Step 4: Alice signs a message using HMAC with the shared secret
    message = b"This is a secure message from Alice to Bob."
    alice_hmac = create_hmac(alice_shared_secret, message)
    print(f"Alice's HMAC: {alice_hmac.hex()}")

    # Step 5: Bob verifies the HMAC using the shared secret
    is_valid = verify_hmac(bob_shared_secret, message, alice_hmac)
    if is_valid:
        print("Bob verifies the HMAC: Message integrity and authenticity are valid.")
    else:
        print("Bob verifies the HMAC: Message integrity and authenticity are NOT valid.")

    # Step 6: Bob sends a message back to Alice using the shared secret
    message_bob = b"This is a secure message from Bob to Alice."
    bob_hmac = create_hmac(bob_shared_secret, message_bob)
    print(f"Bob's HMAC: {bob_hmac.hex()}")

    # Alice verifies Bob's HMAC
    is_valid_bob = verify_hmac(alice_shared_secret, message_bob, bob_hmac)
    if is_valid_bob:
        print("Alice verifies the HMAC: Message integrity and authenticity are valid.")
    else:
        print("Alice verifies the HMAC: Message integrity and authenticity are NOT valid.")

# Run the demo
diffie_hellman_hmac_demo()
