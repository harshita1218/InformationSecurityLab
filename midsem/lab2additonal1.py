import time
import matplotlib.pyplot as plt
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Define messages and keys
messages = [
    "This is the first message.",
    "Here is the second message.",
    "Third message is also here.",
    "Fourth message for testing.",
    "Finally, the fifth message."
]

# Common keys
key_des = b'12345678'  # DES key must be 8 bytes
key_aes_128 = b'0123456789abcdef'  # AES-128 key must be 16 bytes
key_aes_192 = b'0123456789abcdef01234567'  # AES-192 key must be 24 bytes
key_aes_256 = b'0123456789abcdef0123456789abcdef'  # AES-256 key must be 32 bytes

# Modes of operation
modes = {
    "DES_ECB": DES.MODE_ECB,
    "DES_CBC": DES.MODE_CBC,
    "DES_CFB": DES.MODE_CFB,
    "AES_128_ECB": AES.MODE_ECB,
    "AES_128_CBC": AES.MODE_CBC,
    "AES_128_CFB": AES.MODE_CFB,
    "AES_192_ECB": AES.MODE_ECB,
    "AES_192_CBC": AES.MODE_CBC,
    "AES_192_CFB": AES.MODE_CFB,
    "AES_256_ECB": AES.MODE_ECB,
    "AES_256_CBC": AES.MODE_CBC,
    "AES_256_CFB": AES.MODE_CFB
}


# Function to encrypt messages
def encrypt_message(mode, message):
    if 'DES' in mode:
        cipher = DES.new(key_des, modes[mode])
    else:
        if '128' in mode:
            cipher = AES.new(key_aes_128, modes[mode])
        elif '192' in mode:
            cipher = AES.new(key_aes_192, modes[mode])
        else:
            cipher = AES.new(key_aes_256, modes[mode])

    # For CBC and CFB modes, generate a random IV
    iv = get_random_bytes(8 if 'DES' in mode else 16)  # DES uses 8 bytes for IV, AES uses 16 bytes
    if 'CBC' in mode or 'CFB' in mode:
        if 'DES' in mode:
            cipher = DES.new(key_des, modes[mode], iv)
        else:
            cipher = AES.new(key_aes_128 if '128' in mode else key_aes_192 if '192' in mode else key_aes_256,
                             modes[mode], iv)

    return cipher.encrypt(pad(message.encode(), 16)), iv


# Measure execution times
execution_times = {mode: [] for mode in modes.keys()}

for message in messages:
    for mode in modes.keys():
        start_time = time.time()
        ciphertext, iv = encrypt_message(mode, message)
        end_time = time.time()
        execution_times[mode].append(end_time - start_time)

# Calculate average execution times
average_execution_times = {mode: sum(times) / len(times) for mode, times in execution_times.items()}

# Plot the execution times
plt.figure(figsize=(10, 6))
plt.bar(average_execution_times.keys(), average_execution_times.values(), color='skyblue')
plt.xticks(rotation=45)
plt.xlabel('Encryption Mode')
plt.ylabel('Average Execution Time (seconds)')
plt.title('Execution Time of Different Encryption Modes')
plt.grid(axis='y')
plt.tight_layout()
plt.show()
