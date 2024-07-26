def affinecipher(text,key1,key2) :
    result = ""

    # traverse text
    for i in range(len(text)):
        char = text[i]

        # Encrypt uppercase characters
        if (char.isupper()):
            result += chr((((ord(char) -65+key1)*key2) % 26 )+65)

        # Encrypt lowercase characters
        elif(char.islower()) :
            result +=chr((((ord(char) -97+key1)*key2) % 26 )+97)
        else :
            result+=char

    return result
text="I am learning information security "
key1=15
key2=20
print("affineciphered text" + affinecipher(text,key1,key2))

