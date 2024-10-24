import phe.paillier as paillier

# Key generation
public_key, private_key = paillier.generate_paillier_keypair()

# Encrypt data from two parties
data_party1 = 15
data_party2 = 25

encrypted_data1 = public_key.encrypt(data_party1)
encrypted_data2 = public_key.encrypt(data_party2)

# Homomorphic addition (secure sharing)
encrypted_sum = encrypted_data1 + encrypted_data2

# Decrypt the result
decrypted_sum = private_key.decrypt(encrypted_sum)

print("Decrypted sum of shared data:", decrypted_sum)
