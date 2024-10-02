import string


# Helper function to generate the Playfair matrix
def generate_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: 'J' is excluded
    matrix = []
    used_letters = set()

    # Remove duplicates from the key and create the matrix
    for letter in key.upper():
        if letter not in used_letters:
            matrix.append(letter)
            used_letters.add(letter)

    # Fill the remaining matrix with unused letters from the alphabet
    for letter in alphabet:
        if letter not in used_letters:
            matrix.append(letter)

    # Return as 5x5 matrix
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


# Helper function to format the message for encryption
def format_message(message):
    message = message.upper().replace("J", "I").replace(" ", "")

    # Insert 'X' between double letters and pad if necessary
    formatted_message = ""
    i = 0
    while i < len(message):
        formatted_message += message[i]
        if i + 1 < len(message) and message[i] == message[i + 1]:
            formatted_message += "X"
        elif i + 1 < len(message):
            formatted_message += message[i + 1]
        i += 2

    # If the message length is odd, add 'X' at the end
    if len(formatted_message) % 2 != 0:
        formatted_message += "X"

    return formatted_message


# Helper function to find the position of a letter in the matrix
def find_position(letter, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None


# Playfair cipher encryption function
def playfair_encrypt(message, matrix):
    encrypted_message = ""
    message = format_message(message)

    for i in range(0, len(message), 2):
        letter1, letter2 = message[i], message[i + 1]
        row1, col1 = find_position(letter1, matrix)
        row2, col2 = find_position(letter2, matrix)

        # Same row rule
        if row1 == row2:
            encrypted_message += matrix[row1][(col1 + 1) % 5]
            encrypted_message += matrix[row2][(col2 + 1) % 5]
        # Same column rule
        elif col1 == col2:
            encrypted_message += matrix[(row1 + 1) % 5][col1]
            encrypted_message += matrix[(row2 + 1) % 5][col2]
        # Rectangle rule
        else:
            encrypted_message += matrix[row1][col2]
            encrypted_message += matrix[row2][col1]

    return encrypted_message


# Test the Playfair Cipher
key = "GUIDANCE"
message = "The key is hidden under the door pad"

# Generate the Playfair matrix
playfair_matrix = generate_playfair_matrix(key)

# Encrypt the message
encrypted_message = playfair_encrypt(message, playfair_matrix)

# Output the Playfair matrix and encrypted message
print("Playfair Matrix:")
for row in playfair_matrix:
    print(row)

print("\nEncrypted Message:")
print(encrypted_message)
