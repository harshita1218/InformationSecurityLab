def custom_hash(input_string):
    # Initialize hash value
    hash_value = 5381

    # Iterate through each character in the input string
    for char in input_string:
        # Update hash value using the specified formula
        hash_value = ((hash_value << 5) + hash_value) + ord(char)  # Equivalent to hash_value * 33 + ord(char)

        # Ensure hash value is within 32-bit range
        hash_value &= 0xFFFFFFFF  # Apply mask to keep it within 32 bits

    return hash_value


# Test the hash function
if __name__ == "__main__":
    test_string = "Hello, World!"
    hash_result = custom_hash(test_string)
    print(f"The hash value for '{test_string}' is: {hash_result}")
