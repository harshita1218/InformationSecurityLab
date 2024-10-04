# Encrypt the message "Confidential Data" using DES with the following key: "A1B2C3D4". Then decrypt the ciphertext to verify the original message.

# Bit rearrangemnt permute function
def permute(key,permute_table,length):
    permutation=""
    for i in range(0,length):
        permutation += key[permute_table[i]-1]
    return permutation


# Shift left 
def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k

# xor
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

message="Confidential Data"
key="A1B2C3D4"

# Key is only 32 bit right now so we pad so that it becomes 64 bit long
key +=key 

# Convert key for hexadedcimal to binary
key = "{0:08b}".format(int(key, 16))
print(key)

# Parity drop table
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

key = permute(key,keyp,56)
print(key)
# Number of bit shifts
shift_table = [1, 1, 2, 2,
               2, 2, 2, 2,
               1, 2, 2, 2,
               2, 2, 2, 1]

# Key compression from 56 to 48 bits
key_comp = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32]

# Splitting
left = key[0:28]
right = key[28:56]

rkb = []
rk = []
for i in range(0, 16):
    # Shifting the bits by nth shifts by checking from shift table
    left = shift_left(left, shift_table[i])
    right = shift_left(right, shift_table[i])
 
    # Combination of left and right string
    combine_str = left + right
 
    # Compression of key from 56 to 48 bits
    round_key = permute(combine_str, key_comp, 48)
 
    rkb.append(round_key)
    rk.append(bin2hex(round_key))
 
print("Encryption")
cipher_text = bin2hex(encrypt(pt, rkb, rk))
print("Cipher Text : ", cipher_text)
 
print("Decryption")
rkb_rev = rkb[::-1]
rk_rev = rk[::-1]
text = bin2hex(encrypt(cipher_text, rkb_rev, rk_rev))
print("Plain Text : ", text)