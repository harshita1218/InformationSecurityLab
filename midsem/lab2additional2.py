from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Define the key and blocks of data
key = bytes.fromhex("A1B2C3D4E5F60708")  # Key must be 8 bytes for DES
block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

# Convert hex to bytes
block1 = bytes.fromhex(block1_hex)
block2 = bytes.fromhex(block2_hex)

# Create a DES cipher object
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt the blocks
ciphertext1 = cipher.encrypt(pad(block1, DES.block_size))
ciphertext2 = cipher.encrypt(pad(block2, DES.block_size))

# Decrypt the ciphertext to retrieve the original plaintext
decrypted_block1 = unpad(cipher.decrypt(ciphertext1), DES.block_size)
decrypted_block2 = unpad(cipher.decrypt(ciphertext2), DES.block_size)

# Print the results
print("Block 1 Ciphertext (Hex):", ciphertext1.hex().upper())
print("Block 1 Decrypted Plaintext (Hex):", decrypted_block1.hex().upper())
print("Block 2 Ciphertext (Hex):", ciphertext2.hex().upper())
print("Block 2 Decrypted Plaintext (Hex):", decrypted_block2.hex().upper())
