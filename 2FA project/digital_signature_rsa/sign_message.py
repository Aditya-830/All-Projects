import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

KEYS_DIR = "keys"
MESSAGES_DIR = "messages"
SIGNATURES_DIR = "signatures"
os.makedirs(SIGNATURES_DIR, exist_ok=True)

def sign_message(filename):
    msg_path = os.path.join(MESSAGES_DIR, filename)
    sig_path = os.path.join(SIGNATURES_DIR, filename + ".sig")

    with open(msg_path, "rb") as f:
        message = f.read()

    with open(f"{KEYS_DIR}/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"Message signed. Signature saved at: {sig_path}")

if __name__ == "__main__":
    sign_message("message.txt")