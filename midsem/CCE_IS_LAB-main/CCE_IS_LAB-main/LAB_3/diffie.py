from Crypto.PublicKey import DSA
from Crypto.Random import random
import time

p = DSA.generate(1024).p
g = 2 

start_time = time.time()
private_key_A = random.StrongRandom().randint(2, p-2)
private_key_B = random.StrongRandom().randint(2, p-2)
key_generation_time = (time.time() - start_time)*10000


start_time = time.time()
public_key_A = pow(g, private_key_A, p)
public_key_B = pow(g, private_key_B, p)
public_key_generation_time = time.time() - start_time

start_time = time.time()
shared_secret_A = pow(public_key_B, private_key_A, p)
key_exchange_time_A = time.time() - start_time

start_time = time.time()
shared_secret_B = pow(public_key_A, private_key_B, p)
key_exchange_time_B = time.time() - start_time

print(f"Key Generation Time: {key_generation_time:.4f} seconds")
print(f"Public Key Generation Time: {public_key_generation_time:.4f} seconds")
print(f"Key Exchange Time (Peer A): {key_exchange_time_A:.4f} seconds")
print(f"Key Exchange Time (Peer B): {key_exchange_time_B:.4f} seconds")