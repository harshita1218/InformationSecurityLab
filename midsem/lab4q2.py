import os
import logging
from Crypto.Util import number
from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
import json

# Setup logging
logging.basicConfig(filename='key_management_service.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class RabinKeyManagementService:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}
        self.revoked_keys = {}

    def generate_rabin_keys(self):
        """Generate a Rabin public/private key pair."""
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        n = p * q

        # Private key is the pair (p, q)
        private_key = (p, q)
        # Public key is n
        public_key = n

        return public_key, private_key

    def register_hospital(self, hospital_name):
        """Generate and register keys for a hospital."""
        public_key, private_key = self.generate_rabin_keys()
        self.keys[hospital_name] = {
            'public_key': public_key,
            'private_key': private_key,
            'expiration': datetime.now() + timedelta(days=365)
        }
        logging.info(f"Generated keys for {hospital_name}.")
        return public_key, private_key

    def revoke_key(self, hospital_name):
        """Revoke keys for a hospital."""
        if hospital_name in self.keys:
            self.revoked_keys[hospital_name] = self.keys.pop(hospital_name)
            logging.info(f"Revoked keys for {hospital_name}.")
            return True
        return False

    def renew_keys(self):
        """Renew keys for all hospitals."""
        for hospital_name in list(self.keys.keys()):
            public_key, private_key = self.generate_rabin_keys()
            self.keys[hospital_name] = {
                'public_key': public_key,
                'private_key': private_key,
                'expiration': datetime.now() + timedelta(days=365)
            }
            logging.info(f"Renewed keys for {hospital_name}.")

    def get_keys(self, hospital_name):
        """Retrieve keys for a hospital."""
        return self.keys.get(hospital_name, None)

    def audit_logs(self):
        """Retrieve audit logs."""
        with open('key_management_service.log', 'r') as file:
            logs = file.readlines()
        return logs


# Example Usage
def main():
    kms = RabinKeyManagementService()

    # Register hospitals and generate keys
    hospital1_keys = kms.register_hospital("Hospital A")
    hospital2_keys = kms.register_hospital("Hospital B")

    # Retrieve keys
    print("Keys for Hospital A:", kms.get_keys("Hospital A"))
    print("Keys for Hospital B:", kms.get_keys("Hospital B"))

    # Revoke a key
    kms.revoke_key("Hospital A")

    # Renew keys for all hospitals
    kms.renew_keys()

    # Retrieve audit logs
    logs = kms.audit_logs()
    for log in logs:
        print(log.strip())


if __name__ == "__main__":
    main()
