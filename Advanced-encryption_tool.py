import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY_FILE = "aes_key.key"

def generate_key():
    """Generate and save a new AES-256 key."""
    key = os.urandom(32)  # 256-bit key
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    """Load AES-256 key from file or generate a new one."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

KEY = load_key()

def encrypt_file(file_path):
    """Encrypt a file using AES-256."""
    try:
        with open(file_path, "rb") as f:
            plaintext = f.read()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padding_length = 16 - (len(plaintext) % 16)
        plaintext += bytes([padding_length] * padding_length)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        enc_file = file_path + ".enc"

        with open(enc_file, "wb") as f:
            f.write(iv + ciphertext)

        messagebox.showinfo("Success", f"File Encrypted: {enc_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file(file_path):
    """Decrypt a file encrypted with AES-256."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]

        dec_file = file_path.replace(".enc", "")
        with open(dec_file, "wb") as f:
            f.write(plaintext)

        messagebox.showinfo("Success", f"File Decrypted: {dec_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def select_file(encrypt=True):
    """Open a file dialog to select a file for encryption or decryption."""
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if not file_path:
        return
    if encrypt:
        encrypt_file(file_path)
    else:
        decrypt_file(file_path)

# Create GUI Window
root = tk.Tk()
root.title("AES-256 Encryption Tool")
root.geometry("400x220")

tk.Label(root, text="Advanced Encryption Tool (AES-256)", font=("Arial", 12, "bold")).pack(pady=10)

encrypt_button = tk.Button(root, text="Encrypt File", command=lambda: select_file(True), width=20, bg="lightblue")
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(root, text="Decrypt File", command=lambda: select_file(False), width=20, bg="lightgreen")
decrypt_button.pack(pady=5)

exit_button = tk.Button(root, text="Exit", command=root.quit, width=20, bg="red")
exit_button.pack(pady=5)

root.mainloop()
