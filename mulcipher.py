def mulcipher(text,key) :
    result = ""

    # traverse text
    for i in range(len(text)):
        char = text[i]

        # Encrypt uppercase characters
        if (char.isupper()):
            result += chr((((ord(char) -65)*key) % 26 )+65)

        # Encrypt lowercase characters
        elif(char.islower()) :
            result +=chr((((ord(char) -97)*key) % 26 )+97)
        else :
            result+=char

    return result
text="I am learning information security "
key=15
print("mulciphered text" + mulcipher(text,key))

