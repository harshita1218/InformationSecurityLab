#Encrypt the message "I am learning information security" using one of the following ciphers. 
#Ignore the space between words. Decrypt the message to get the original plaintext: 
#a) Additive cipher with key = 20 
#b) Multiplicative cipher with key = 15 
#c) Affine cipher with key = (15, 20)

#Additive Cipher
def additive_encrypt(message, key):
    encrypted_message = ""
    for char in message:
        if (char.isalpha()):
            if (char.isupper()):
                encrypted_message += chr((ord(char) + key-ord('A')) % 26 +ord('A'))
            else:
                encrypted_message += chr((ord(char) + key-ord('a')) % 26 +ord('a'))
        else:
            encrypted_message += char
    return encrypted_message

def additive_decrypt(message, key):
    decrypted_message = ""
    for char in message:
        if (char.isalpha()):
            if (char.isupper()):
                decrypted_message += chr((ord(char) - key-ord('A')) % 26 +ord('A'))
            else:
                decrypted_message += chr((ord(char) - key-ord('a')) % 26 +ord('a'))
        else:
            decrypted_message += char
    return decrypted_message
    
# Multiplicative Cipher
def multiplicative_encrypt(message, key):
    encrypted_message = ""
    for char in message:
        if (char.isalpha()):
            if (char.isupper()):
                encrypted_message += chr(((ord(char) - ord('A')) * key) % 26 + ord('A'))
            else:
                encrypted_message += chr(((ord(char) - ord('a')) * key) % 26 + ord('a'))
        else:
            encrypted_message += char
    return encrypted_message

def multiplicative_decrypt(message, key):
    decrypted_message = ""
    for char in message:
        if (char.isalpha()):
            if (char.isupper()):
                decrypted_message += chr(((ord(char) - ord('A')) * pow(key, -1, 26))%26 +ord('A'))
            else:
                decrypted_message += chr(((ord(char) - ord('a')) * pow(key, -1, 26))%26 +ord('a'))
        else:
            decrypted_message += char
    return decrypted_message

#Affine Cipher
def affine_encrypt(message, key1, key2):
    encrypted_message = ""
    for char in message:
        if (char.isalpha()):
            if (char.isupper()):
                encrypted_message += chr(((ord(char)-65)*key1 +key2)%26 +65)
            else:
                encrypted_message += chr(((ord(char)-97)*key1 +key2)%26 +97)
        else:
            encrypted_message += char
    return encrypted_message

def affine_decrypt(message, key1, key2):
    key1_inv = pow(key1, -1, 26)
    decrypted_message = ""
    for char in message:
        if (char.isalpha()):
            if (char.isupper()):
                decrypted_message += chr(((ord(char)-65-key2)*key1_inv)%26 +65)
            else:
                decrypted_message += chr(((ord(char)-97-key2)*key1_inv)%26 +97)
        else:
            decrypted_message += char
    return decrypted_message
                    
    
message = "I am learning information security"
key2 = 20
key1 = 15

encrypted_message = additive_encrypt(message,key2)
print(f"Encrypted message:{encrypted_message}")
decrypted_message = additive_decrypt(encrypted_message,key2)
print(f"Decrypted message:{decrypted_message}")

encrypted_message = multiplicative_encrypt(message,key1)
print(f"Encrypted message:{encrypted_message}")
decrypted_message = multiplicative_decrypt(encrypted_message,key1)
print(f"Decrypted message:{decrypted_message}")

encrypted_message = affine_encrypt(message,key1,key2)
print(f"Encrypted message:{encrypted_message}")
decrypted_message = affine_decrypt(encrypted_message,key1,key2)
print(f"Decrypted message:{decrypted_message}")