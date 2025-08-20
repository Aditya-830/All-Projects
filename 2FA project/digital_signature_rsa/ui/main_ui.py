import tkinter as tk
from tkinter import filedialog, messagebox
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

KEYS_DIR = "../keys"
SIGNATURES_DIR = "../signatures"
MESSAGES_DIR = "../messages"

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(SIGNATURES_DIR, exist_ok=True)
os.makedirs(MESSAGES_DIR, exist_ok=True)

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature System (RSA)")
        self.root.geometry("450x350")
        self.root.configure(bg="#f0f4f7")

        # Title label
        title_label = tk.Label(root, text="Digital Signature Verification System", 
                               font=("Helvetica", 30, "bold"), fg="#003366", bg="#f0f4f7")
        title_label.pack(pady=20)

        # Button frame
        button_frame = tk.Frame(root, bg="#f0f4f7")
        button_frame.pack(pady=10)

        # Buttons with consistent style
        btn_style = {"font": ("Arial", 20), "bg": "#007acc", "fg": "white", "activebackground": "#005f99",
                     "activeforeground": "blue", "relief": "raised", "bd": 3, "width": 25, "padx": 5, "pady": 5}

        tk.Button(button_frame, text="🔐 Generate RSA Keys", command=self.generate_keys, **btn_style).pack(pady=10)
        tk.Button(button_frame, text="✍️  Sign Message/File", command=self.sign_message, **btn_style).pack(pady=10)
        tk.Button(button_frame, text="✅ Verify Signature", command=self.verify_signature, **btn_style).pack(pady=10)

    def generate_keys(self):
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

        messagebox.showinfo("Success", "✅ RSA keys generated successfully!")

    def sign_message(self):
        file_path = filedialog.askopenfilename(title="Select file to sign")
        if not file_path:
            return

        with open(file_path, "rb") as f:
            message = f.read()

        try:
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

            sig_path = os.path.join(SIGNATURES_DIR, os.path.basename(file_path) + ".sig")
            with open(sig_path, "wb") as f:
                f.write(signature)

            messagebox.showinfo("Success", f"📝 File signed successfully.\nSignature saved at:\n{sig_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify_signature(self):
        file_path = filedialog.askopenfilename(title="Select file to verify")
        if not file_path:
            return
        sig_path = filedialog.askopenfilename(title="Select signature file")
        if not sig_path:
            return

        with open(file_path, "rb") as f:
            message = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()

        try:
            with open(f"{KEYS_DIR}/public_key.pem", "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            messagebox.showinfo("Success", "🎉 Signature is valid.")
        except Exception as e:
            messagebox.showerror("Invalid Signature", f"❌ Verification failed:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
