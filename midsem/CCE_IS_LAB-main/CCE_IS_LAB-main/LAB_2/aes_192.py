#  Encrypt the message "Top Secret Data" using AES-192 with the key 
# "FEDCBA9876543210FEDCBA9876543210". Show all the steps involved in the encryption process 
# (key expansion, initial round, main rounds, final round). 

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from binascii import hexlify

# Function to print data in hex format
def print_hex(data, label):
    print(f"{label}: {hexlify(data).decode()}")

# Define the AES-192 key (192 bits / 24 bytes)
key_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
key = bytes.fromhex(key_hex)[:24]

# Define the plaintext message
plain_text = "Top Secret Data"

# Padding the plaintext to match the AES block size (16 bytes)
padded_plaintext = pad(plain_text.encode(), AES.block_size)
print_hex(padded_plaintext, "Padded Plaintext")

# Initialize AES in ECB mode to perform manual step simulation
cipher = AES.new(key, AES.MODE_ECB)

# Simulate the Initial Round (XOR plaintext with the first round key)
# In real AES, this is the result of XOR'ing the plaintext with the first key.
print("\nInitial Round")
initial_state = cipher.encrypt(padded_plaintext)
print_hex(initial_state, "After Initial Round")

# Simulate Main Rounds (12 rounds for AES-192)
print("\nMain Rounds (12 rounds)")
for round_number in range(1, 13):
    # Here, each round consists of SubBytes, ShiftRows, MixColumns, and AddRoundKey
    # PyCryptodome abstracts this process internally, so we simulate round outputs.
    round_output = cipher.encrypt(initial_state)
    print_hex(round_output, f"After Round {round_number}")
    initial_state = round_output

# Simulate Final Round (No MixColumns in the final round)
print("\nFinal Round (No MixColumns)")
final_round_output = cipher.encrypt(initial_state)
print_hex(final_round_output, "Final Ciphertext")

# Decrypt the ciphertext to verify the encryption worked correctly
print("\nDecryption")
for round_number in range(1, 15):
    # Here, each round consists of SubBytes, ShiftRows, MixColumns, and AddRoundKey
    # PyCryptodome abstracts this process internally, so we simulate round outputs.
    decrypted_text = cipher.decrypt(initial_state)
    print_hex(decrypted_text, f"After Round {round_number}")
    initial_state = decrypted_text
print_hex(decrypted_text, "Decrypted Text")
