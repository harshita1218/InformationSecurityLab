
#En(x) = (x + n) mod 26 and the Decryption formula is Dn(x) = (x – n) mod 26 




def addcipher(text,key) :
    result = ""

    # traverse text
    for i in range(len(text)):
        char = text[i]

        # Encrypt uppercase characters
        if (char.isupper()):
            result += chr((ord(char) + key-65) % 26 + 65)

        # Encrypt lowercase characters
        elif(char.islower()) :
            result += chr((ord(char) + key - 97) % 26 + 97)
        else :
            result+=char

    return result

#check the above function
def main():
 text = "I am learning information security "
 key = 20
 print ("Text  : " + text)
 print ("Shift : " + str(key))
 print ("Cipher: " + addcipher(text,key))
 print ("Decrypt:"+addreverse(addcipher(text,key),key)


def addreverse(addcipher(text,key),key) :
   new=""
   for i in range(len(result)):
     charr=result[i]
     if(charr.isupper()):
       new+=chr((ord(charr)-key-65)%26+65)
     elif(charr.islower()):
      new+=chr((ord(charr)-key-97)%26+97)
     else:
      new+=charr
  return new
