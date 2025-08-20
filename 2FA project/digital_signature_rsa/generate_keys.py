import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{KEYS_DIR}/private_key.pem", "wb") as f:
        f.write(pem_private)

    with open(f"{KEYS_DIR}/public_key.pem", "wb") as f:
        f.write(pem_public)

    print("RSA key pair generated and saved in /keys/")

if __name__ == "__main__":
    generate_keys()