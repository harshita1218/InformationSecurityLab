from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json

# AES Encryption/Decryption for Text
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv': iv, 'ciphertext': ct})

def aes_decrypt(key, enc_data):
    try:
        b64 = json.loads(enc_data)
        iv = base64.b64decode(b64['iv'])
        ct = base64.b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError):
        print("Decryption error")

# 1a. Create the dataset (list of quotes)
quotes = [
    "May the Force be with you",                   # ID 0
    "I am going to make him an offer he can't refuse",  # ID 1
    "Life is a box of chocolates",                 # ID 2
    "I've a feeling we're not in Kansas anymore",  # ID 3
    "You had me at Hello",                         # ID 4
    "Houston, we have a problem",                  # ID 5
    "There's no place like home",                  # ID 6
    "You can't handle the truth !",                 # ID 7
    "I'll be back",                                # ID 8
    "Elementary, my dear Watson"                   # ID 9
]

# 1b. AES encryption and decryption
# Generate AES encryption key
aes_key = get_random_bytes(16)

# 1c. Build the inverted index and encrypt it
inverted_index = {}

# Encrypt the documents
encrypted_quotes = [aes_encrypt(aes_key, quote) for quote in quotes]

# Build an inverted index (unencrypted for now)
for doc_id, quote in enumerate(quotes):
    for word in quote.lower().split():
        if word not in inverted_index:
            inverted_index[word] = []
        inverted_index[word].append(doc_id)

# Encrypt the inverted index
encrypted_inverted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_word = aes_encrypt(aes_key, word)  # Encrypt the word
    encrypted_doc_ids = aes_encrypt(aes_key, json.dumps(doc_ids))  # Encrypt the document IDs list
    encrypted_inverted_index[encrypted_word] = encrypted_doc_ids

# 1d. Implement the search function (with SSE)
def search(query):
    # Encrypt the search query
    encrypted_query = aes_encrypt(aes_key, query.lower())

    # Search the encrypted inverted index
    found = False
    for enc_word in encrypted_inverted_index:
        if aes_decrypt(aes_key, enc_word) == query.lower():  # Check if the decrypted word matches the query
            found = True
            # Get the encrypted document IDs
            enc_doc_ids = encrypted_inverted_index[enc_word]
            doc_ids = json.loads(aes_decrypt(aes_key, enc_doc_ids))  # Decrypt document IDs

            # Display the corresponding encrypted documents (quotes)
            print(f"Search results for '{query}':")
            for doc_id in doc_ids:
                decrypted_quote = aes_decrypt(aes_key, encrypted_quotes[doc_id])
                print(f"Document {doc_id}: {decrypted_quote}")
            break

    if not found:
        print(f"No documents found for the query '{query}'.")

# Example searches with encrypted index
if __name__ == "__main__":
    print("\nSearch for 'truth':")
    search("truth")

    print("\nSearch for 'force':")
    search("force")

    print("\nSearch for 'home':")
    search("home")
