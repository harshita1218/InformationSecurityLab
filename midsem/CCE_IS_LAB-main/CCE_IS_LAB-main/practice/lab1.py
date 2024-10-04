def additive_encrypt(message, key):
    encrypted=""
    message = message.casefold()
    for ch in message:
        encrypted += chr((ord(ch)+key-ord('a'))%26+ord('a'))
    return encrypted

def additive_decrypt(message, key):
    decrypted=""
    message = message.casefold()
    for ch in message:
        decrypted += chr((ord(ch)-key-ord('a'))%26+ord('a'))
    return decrypted

def multiplicative_encrypt(message, key):
    encrypted=""
    message = message.casefold()
    for ch in message:
        encrypted += chr(((ord(ch)-ord('a'))*key)%26+ord('a'))
    return encrypted

def multiplicative_decrypt(message, key):
    decrypted=""
    message = message.casefold()
    key_inv = pow(key,-1,26)
    for ch in message:
        decrypted += chr(((ord(ch)-ord('a'))*key_inv)%26+ord('a'))
    return decrypted

def affine_encrypt(message, key1, key2):
    encrypted=""
    message = message.casefold()
    for ch in message:
        encrypted += chr(((ord(ch)-ord('a'))*key1+key2)%26+ord('a'))
    return encrypted

def affine_decrypt(message, key1, key2):
    decrypted=""
    message = message.casefold()
    key1_inv = pow(key1,-1,26)
    for ch in message:
        decrypted += chr(((ord(ch)-ord('a')-key2)*key1_inv)%26+ord('a'))
    return decrypted

def autokey_encrypt(message, key):
    message = message.casefold().replace(" ", "")
    key = key.casefold().replace(" ", "")
    if len(key) < len(message):
        key += message[len(key):]  

    encrypted_message = ""
    for i in range(len(message)):
        shift = ord(key[i]) - ord('a')
        shift = key
        encrypted_message += chr((ord(message[i]) - ord('a') + shift) % 26 + ord('a'))
    return encrypted_message

def autokey_decrypt(message, key):
    message = message.casefold().replace(" ", "")
    key = key.casefold().replace(" ", "")
    decrypted_message = ""
    for i in range(len(message)):
        shift = ord(key[i]) - ord('a')
        decrypted_message += chr((ord(message[i]) - ord('a') - shift) % 26 + ord('a'))
        key += decrypted_message[-1]  
    return decrypted_message


enc = autokey_encrypt("attackistoday","m")
print(enc)