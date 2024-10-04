#Use the Playfair cipher to encipher the message "The key is hidden under the door pad". The secret key can be made by filling the first and part of the second row with the word "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.

#Playfair Cipher
def get_array_index(matrix,ch):
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            if(matrix[i][j]==ch):
                return i,j
    return -1          

def create_matrix(key):
    key=key.casefold()
    matrix = []
    alphabet = 'abcdefghiklmnopqrstuvwxyz' #excluding j in since it is less 
    for i in range(5):
        row = []
        for j in range(5):
            if key:
                row.append(key[0])
                alphabet=alphabet.replace(key[0],"")
                key=key.replace(key[0],"")
            else:
                row.append(alphabet[0])
                alphabet=alphabet.replace(alphabet[0],"")
        matrix.append(row)
    return matrix

def encrypt_playfair(message,matrix):
    encrypted_message=""
    message=message.casefold()
    message=message.replace(" ","")
    if(len(message)%2!=0):
        message+='x'
    message=message.replace('j','i') #We can take the j as an i since we ignored it pehle
    for i in range(0,len(message),2):
        a,b = get_array_index(matrix,message[i])
        c,d = get_array_index(matrix,message[i+1])
        if(a==c):
            encrypted_message+=matrix[a][(b+1)%5]
            encrypted_message+=matrix[a][(d+1)%5]
        elif(b==d):
            encrypted_message+=matrix[(a+1)%5][b]
            encrypted_message+=matrix[(c+1)%5][d]
        else:
            encrypted_message+=matrix[a][d]
            encrypted_message+=matrix[c][b]
    return encrypted_message
        
def decrypt_playfair(message,matrix):
    decrypted_message=""
    for i in range(0,len(message),2):
        a,b = get_array_index(matrix,message[i])
        c,d = get_array_index(matrix,message[i+1])
        if(a==c):
            decrypted_message+=matrix[a][(b-1)%5]
            decrypted_message+=matrix[a][(d-1)%5]
        elif(b==d):
            decrypted_message+=matrix[(a-1)%5][b]
            decrypted_message+=matrix[(c-1)%5][d]
        else:
            decrypted_message+=matrix[a][d]
            decrypted_message+=matrix[c][b]
    return decrypted_message        


matrix = create_matrix("GUIDANCE")
print(matrix)
message = "The key is hidden under the door pad"
encrypted_message = encrypt_playfair(message,matrix)
print(encrypted_message)
decrypted_message=decrypt_playfair(encrypted_message, matrix)
print(decrypted_message)