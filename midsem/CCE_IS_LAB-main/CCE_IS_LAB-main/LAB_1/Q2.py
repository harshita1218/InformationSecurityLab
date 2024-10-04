# Encrypt the message "the house is being sold tonight" using one of the following ciphers. 
# Ignore the space between words. Decrypt the message to get the original plaintext: 
# • Vigenere cipher with key: "dollars" 
# • Autokey cipher with key = 7

#Vigenere Key
def vigenere_key(message,key):
    if len(message) == len(key):
        return key
    i = 0
    new_key="" # Kept the spaces matching message in the key so that we can retain those while decrypting
    for ch in message:
        if ch!=' ':
            new_key+=key[i%len(key)]
            i = (i+1)
        else:
            new_key+=' '
    return new_key

def vigenere_encrypt(message, key):
    encrypted_message = ""
    for i in range(len(message)):
        char = message[i]
        key_char = key[i]
        if char.isalpha():
            shift = ord(key_char.upper()) - ord('A')
            if char.isupper():
                encrypted_message += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_message += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            encrypted_message += char
    return encrypted_message

def vignere_decrypt(message, key):
    decrypted_message = ""
    for i in range(len(message)):
        char = message[i]
        key_char = key[i]
        if char.isalpha():
            shift = ord(key_char.upper()) - ord('A')
            if char.isupper():
                decrypted_message += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_message += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            decrypted_message += char
    return decrypted_message

# Autokey cipher
def autokey_encrypt(message, key):
    encrypted_message=""
    message=message.casefold()
    message = message.replace(" ","") 
    shift = (ord(message[0])+key-ord('a'))%26
    encrypted_message = chr(shift+ord('a'))
    for i in range(1,len(message)):
        shift = ord(message[i-1])-ord('a')
        encrypted_message += chr((ord(message[i])-ord('a')+shift)%26+ord('a'))
    return encrypted_message

def autokey_decrypt(message,key):
    decrypted_message=""
    shift = (ord(message[0])-key-ord('a'))%26
    decrypted_message = chr(shift+ord('a'))
    for i in range(1,len(message)):
        shift = ord(decrypted_message[i-1])-ord('a')
        decrypted_message += chr((ord(message[i])-ord('a')-shift)%26+ord('a'))
    return decrypted_message



#Modifications for string key in autokey cipher are commented
# def autokey_encrypt(message, key):
#     message = message.casefold().replace(" ", "")
#     key = key.casefold().replace(" ", "")
#     if len(key) < len(message):
#         key += message[len(key):]  

#     encrypted_message = ""
#     for i in range(len(message)):
#         shift = ord(key[i]) - ord('a')
#         shift = key
#         encrypted_message += chr((ord(message[i]) - ord('a') + shift) % 26 + ord('a'))
#     return encrypted_message

# def autokey_decrypt(message, key):
#     message = message.casefold().replace(" ", "")
#     key = key.casefold().replace(" ", "")
#     decrypted_message = ""
#     for i in range(len(message)):
#         shift = ord(key[i]) - ord('a')
#         decrypted_message += chr((ord(message[i]) - ord('a') - shift) % 26 + ord('a'))
#         key += decrypted_message[-1]  
#     return decrypted_message

message = "the house is being sold tonight"
key = vigenere_key(message,'dollars')
encrypted_message = vigenere_encrypt(message,key)
print(f"Encrypted message:{encrypted_message}")
decrypted_message = vignere_decrypt(encrypted_message,key)
print(f"Decrypted message:{decrypted_message}")


key=7
encrypted_message = autokey_encrypt(message,key)
print(f"Encrypted message:{encrypted_message}")
decrypted_message = autokey_decrypt(encrypted_message,key)
print(f"Decrypted message:{decrypted_message}")
            