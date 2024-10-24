#LAB4SecureCorpRoleBasedAccess

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Initial role permissions
roles = {
    "Finance": ["read_financial_reports", "write_financial_reports"],
    "HR": ["read_employee_data", "write_employee_data"],
    "SupplyChain": ["read_procurement_orders", "write_procurement_orders"],
    "admin": ["revoke_permissions", "read_financial_reports", "read_employee_data", "read_procurement_orders"]
    # Admin has no explicit permissions but can revoke access
}

# Key management system (basic implementation)
key_store = {}


# Function to generate RSA key pairs for a role
def generate_keys(role):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    key_store[role] = {"public_key": public_key, "private_key": private_key}
    return public_key, private_key


# Get the public key for a role
def get_public_key(role):
    return key_store.get(role, {}).get("public_key")


# Get the private key for a role
def get_private_key(role):
    return key_store.get(role, {}).get("private_key")


# Encrypt message with RSA public key
def encrypt_message(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return b64encode(encrypted_message).decode()


# Decrypt message with RSA private key
def decrypt_message(encrypted_message, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher_rsa.decrypt(b64decode(encrypted_message.encode()))
    return decrypted_message.decode()


# Check access based on role and permission
def check_access(role, permission):
    return permission in roles.get(role, [])


# Function to add a permission to a role
def add_permission(role, permission):
    if role in roles:
        if permission not in roles[role]:
            roles[role].append(permission)
        else:
            print(f"Role '{role}' already has permission '{permission}'")
    else:
        print(f"Role '{role}' does not exist")


# Function to revoke a permission from a role
def revoke_permission(role, permission):
    if role in roles and permission in roles[role]:
        roles[role].remove(permission)
        print(f"Permission '{permission}' revoked from role '{role}'")
    else:
        print(f"Role '{role}' does not have permission '{permission}'")


# User interaction: select role and action
def user_interaction():
    # Simulate existing keys for roles
    for role in roles.keys():
        generate_keys(role)

    while True:
        print("\nAvailable roles: Finance, HR, SupplyChain, admin")
        role = input("Enter your role: ")

        if role not in roles:
            print("Invalid role. Please try again.")
            continue

        print("\nAvailable actions: ")
        print("1. View Financial Report (requires 'read_financial_reports')")
        print("2. View Employee Data (requires 'read_employee_data')")
        print("3. View Procurement Orders (requires 'read_procurement_orders')")
        print("4. Revoke Access (admin only)")

        action = input("Choose an action: ")

        # Encrypt and decrypt based on role access
        if action == "1":
            if check_access(role, "read_financial_reports"):
                message = "Financial Report: Q3 Profits increased by 20%"
                encrypted_message = encrypt_message(message, get_public_key("Finance"))
                print("Encrypted Financial Report:", encrypted_message)
                print("Decrypted Financial Report (Finance):",
                      decrypt_message(encrypted_message, get_private_key("Finance")))
            else:
                print("Access denied: You do not have permission to read financial reports.")

        elif action == "2":
            if check_access(role, "read_employee_data"):
                print("Access granted: Viewing employee data...")
            else:
                print("Access denied: You do not have permission to read employee data.")

        elif action == "3":
            if check_access(role, "read_procurement_orders"):
                print("Access granted: Viewing procurement orders...")
            else:
                print("Access denied: You do not have permission to read procurement orders.")

        elif action == "4":
            if role == "admin":  # Only admins can revoke permissions
                role_to_revoke = input("Enter the role to revoke access from: ")
                permission_to_revoke = input("Enter the permission to revoke: ")
                revoke_permission(role_to_revoke, permission_to_revoke)
            else:
                print("Access denied: Only admins can revoke permissions.")

        else:
            print("Invalid action. Please try again.")

        continue_prompt = input("Do you want to perform another action? (yes/no): ")
        if continue_prompt.lower() != 'yes':
            break


# Run the program
user_interaction()
