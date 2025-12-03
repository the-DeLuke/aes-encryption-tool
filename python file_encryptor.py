import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

class CryptoManager:
    """Handles the core AES-256 encryption and decryption logic."""
    
    def __init__(self):
        self.backend = default_backend()
        self.salt_size = 16
        self.nonce_size = 12 # Recommended size for GCM
        self.key_size = 32   # 32 bytes = 256 bits (AES-256)
        self.iterations = 100_000

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a 256-bit key from the password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, file_path, password):
        """Encrypts a file using AES-256-GCM."""
        try:
            # 1. Generate a random salt and nonce (IV)
            salt = os.urandom(self.salt_size)
            nonce = os.urandom(self.nonce_size)

            # 2. Derive the 256-bit key
            key = self.derive_key(password, salt)

            # 3. Read the file data
            with open(file_path, 'rb') as f:
                data = f.read()

            # 4. Encrypt the data
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()

            # 5. Get the authentication tag (integrity check)
            tag = encryptor.tag

            # 6. Write the output file (Salt + Nonce + Tag + Ciphertext)
            output_path = file_path + ".enc"
            with open(output_path, 'wb') as f:
                f.write(salt)
                f.write(nonce)
                f.write(tag)
                f.write(ciphertext)
            
            return True, output_path
        except Exception as e:
            return False, str(e)

    def decrypt_file(self, file_path, password):
        """Decrypts a file using AES-256-GCM."""
        try:
            # 1. Read the encrypted file
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # 2. Extract metadata (Salt, Nonce, Tag)
            salt = file_data[:self.salt_size]
            nonce = file_data[self.salt_size : self.salt_size + self.nonce_size]
            tag = file_data[self.salt_size + self.nonce_size : self.salt_size + self.nonce_size + 16]
            ciphertext = file_data[self.salt_size + self.nonce_size + 16:]

            # 3. Derive the same key
            key = self.derive_key(password, salt)

            # 4. Decrypt and Verify
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            # 5. Write the decrypted output (Remove .enc extension)
            output_path = file_path.replace(".enc", "")
            # If file didn't have .enc, append .dec to avoid overwriting original if it exists
            if output_path == file_path:
                output_path += ".dec"

            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            return True, output_path
        except Exception as e:
            return False, "Invalid password or corrupted file."

class EncryptionApp:
    """The Graphical User Interface (GUI) for the tool."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 File Encryptor")
        self.root.geometry("500x350")
        self.root.resizable(False, False)
        
        self.crypto = CryptoManager()
        self.selected_file = None

        self.setup_ui()

    def setup_ui(self):
        # Styles
        style = ttk.Style()
        style.configure("TButton", padding=6, font=('Helvetica', 10))
        style.configure("TLabel", font=('Helvetica', 11))

        # Main Frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Secure File Encryption", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=(0, 20))

        # File Selection
        self.file_label = ttk.Label(main_frame, text="No file selected", foreground="gray")
        self.file_label.pack(pady=(0, 5))
        
        select_btn = ttk.Button(main_frame, text="Select File", command=self.select_file)
        select_btn.pack(fill=tk.X, pady=(0, 20))

        # Password Input
        pass_label = ttk.Label(main_frame, text="Enter Password:")
        pass_label.pack(anchor=tk.W)
        
        self.password_entry = ttk.Entry(main_frame, show="*")
        self.password_entry.pack(fill=tk.X, pady=(0, 20))

        # Action Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        encrypt_btn = ttk.Button(btn_frame, text="🔒 ENCRYPT", command=self.perform_encryption)
        encrypt_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        decrypt_btn = ttk.Button(btn_frame, text="🔓 DECRYPT", command=self.perform_decryption)
        decrypt_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))

        # Status
        self.status_label = ttk.Label(main_frame, text="Ready", font=('Helvetica', 9))
        self.status_label.pack(side=tk.BOTTOM, pady=10)

    def select_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.selected_file = filename
            # Show only the tail of the path to keep it clean
            display_name = "..." + filename[-40:] if len(filename) > 40 else filename
            self.file_label.config(text=f"Selected: {display_name}", foreground="black")

    def perform_encryption(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        self.status_label.config(text="Encrypting...", foreground="blue")
        self.root.update()

        success, result = self.crypto.encrypt_file(self.selected_file, password)
        
        if success:
            self.status_label.config(text="Encryption Complete", foreground="green")
            messagebox.showinfo("Success", f"File Encrypted Successfully!\nSaved as: {result}")
        else:
            self.status_label.config(text="Error", foreground="red")
            messagebox.showerror("Error", f"Encryption failed:\n{result}")

    def perform_decryption(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        self.status_label.config(text="Decrypting...", foreground="blue")
        self.root.update()

        success, result = self.crypto.decrypt_file(self.selected_file, password)
        
        if success:
            self.status_label.config(text="Decryption Complete", foreground="green")
            messagebox.showinfo("Success", f"File Decrypted Successfully!\nSaved as: {result}")
        else:
            self.status_label.config(text="Error", foreground="red")
            messagebox.showerror("Error", f"Decryption failed:\n{result}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()