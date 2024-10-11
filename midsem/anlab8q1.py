import random
import hashlib
from Crypto.Util import number

# Paillier encryption/decryption
class Paillier:
    def __init__(self, keysize=512):
        self.keysize = keysize
        self.public_key, self.private_key = self.generate_keypair()

    def generate_keypair(self):
        p = number.getPrime(self.keysize)
        q = number.getPrime(self.keysize)
        n = p * q
        g = n + 1  # In practice, g = n + 1 is commonly used
        lambda_n = (p - 1) * (q - 1)
        mu = number.inverse(lambda_n, n)  # Modular inverse
        return (n, g), (lambda_n, mu)

    def encrypt(self, pub_key, m, r=None):
        n, g = pub_key
        if r is None:
            r = random.randint(1, n - 1)  # Generate random r if not provided
        c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
        return c

    def decrypt(self, priv_key, pub_key, c):
        n, _ = pub_key
        lambda_n, mu = priv_key
        u = pow(c, lambda_n, n * n)
        l = (u - 1) // n
        m = (l * mu) % n
        return m


# Create dataset
documents = {
    "doc1": "the quick brown fox jumps over the lazy dog",
    "doc2": "a quick brown fox runs across the road",
    "doc3": "brown bears are bigger than foxes",
    "doc4": "the road is long and winding",
    "doc5": "running can be a great exercise",
    "doc6": "dogs and foxes are both animals",
    "doc7": "the sun rises in the east",
    "doc8": "a slow brown bear walks the road",
    "doc9": "dogs are man's best friend",
    "doc10": "a fox and a dog became friends"
}


# Create an encrypted index
def create_encrypted_index(documents, paillier):
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            word_hash = number.bytes_to_long(hashlib.sha256(word.encode()).digest())
            
            # Use a fixed random 'r' value for the encryption to ensure consistency
            r = 42  # Consistent value of r for all words
            encrypted_word = paillier.encrypt(paillier.public_key, word_hash, r)

            if encrypted_word not in index:
                index[encrypted_word] = []
            
            index[encrypted_word].append(doc_id)
    return index


# Search encrypted index
def search_encrypted_index(query, encrypted_index, paillier):
    query_hash = number.bytes_to_long(hashlib.sha256(query.encode()).digest())
    
    # Use the same fixed 'r' for the search query
    r = 42  # Same consistent r for search query
    encrypted_query = paillier.encrypt(paillier.public_key, query_hash, r)
    
    # Compare with precomputed encrypted words
    if encrypted_query in encrypted_index:
        return encrypted_index[encrypted_query]
    else:
        return []


# Initialize Paillier encryption system
paillier = Paillier(keysize=512)

# Create the encrypted index
encrypted_index = create_encrypted_index(documents, paillier)

# Perform a search query
query = "brown"
results = search_encrypted_index(query, encrypted_index, paillier)

# Output the results
print(f"Documents containing the word '{query}':", results)
