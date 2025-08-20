import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

KEYS_DIR = "keys"
MESSAGES_DIR = "messages"
SIGNATURES_DIR = "signatures"

def verify_signature(filename):
    msg_path = os.path.join(MESSAGES_DIR, filename)
    sig_path = os.path.join(SIGNATURES_DIR, filename + ".sig")

    with open(msg_path, "rb") as f:
        message = f.read()

    with open(sig_path, "rb") as f:
        signature = f.read()

    with open(f"{KEYS_DIR}/public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is VALID.")
    except Exception as e:
        print(f"Signature is INVALID: {e}")

if __name__ == "__main__":
    verify_signature("message.txt")