import time
import random


# Function to generate a large prime number (for simplicity, we use a small prime here)
def generate_large_prime():
    # In real applications, use a secure method to generate large prime numbers
    return 23  # Small prime for demonstration


# Function to perform modular exponentiation
def power_mod(base, exponent, mod):
    return pow(base, exponent, mod)


# Class representing a peer in the Diffie-Hellman protocol
class DiffieHellmanPeer:
    def __init__(self, peer_name):
        self.peer_name = peer_name
        self.p = generate_large_prime()  # Shared prime number
        self.g = 5  # Shared base (generator)
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_keys(self):
        # Generate a private key
        self.private_key = random.randint(1, self.p - 1)  # Random private key
        # Compute public key
        self.public_key = power_mod(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public_key):
        # Compute the shared secret key
        self.shared_secret = power_mod(other_public_key, self.private_key, self.p)


def main():
    # Create two peers
    alice = DiffieHellmanPeer("Alice")
    bob = DiffieHellmanPeer("Bob")

    # Measure key generation time for Alice
    start_time = time.time()
    alice.generate_keys()
    alice_key_gen_time = time.time() - start_time
    print(f"{alice.peer_name} Key Generation Time: {alice_key_gen_time:.6f} seconds")

    # Measure key generation time for Bob
    start_time = time.time()
    bob.generate_keys()
    bob_key_gen_time = time.time() - start_time
    print(f"{bob.peer_name} Key Generation Time: {bob_key_gen_time:.6f} seconds")

    # Exchange public keys
    print(f"{alice.peer_name} Public Key: {alice.public_key}")
    print(f"{bob.peer_name} Public Key: {bob.public_key}")

    # Measure key exchange time for Alice
    start_time = time.time()
    alice.compute_shared_secret(bob.public_key)
    alice_key_exchange_time = time.time() - start_time
    print(f"{alice.peer_name} Key Exchange Time: {alice_key_exchange_time:.6f} seconds")

    # Measure key exchange time for Bob
    start_time = time.time()
    bob.compute_shared_secret(alice.public_key)
    bob_key_exchange_time = time.time() - start_time
    print(f"{bob.peer_name} Key Exchange Time: {bob_key_exchange_time:.6f} seconds")

    # Display the shared secret keys
    print(f"{alice.peer_name} Shared Secret: {alice.shared_secret}")
    print(f"{bob.peer_name} Shared Secret: {bob.shared_secret}")


if __name__ == "__main__":
    main()
