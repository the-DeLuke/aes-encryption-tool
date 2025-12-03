# AES-256 File Encryptor (Python + Tkinter)

A simple and secure GUI-based file encryption tool built with **AES-256-GCM**, **PBKDF2 key derivation**, and **Tkinter** for an easy-to-use interface.
This application allows you to **encrypt** and **decrypt** any file using a password-based encryption system.

---

## 🔐 Features

* AES-256-GCM encryption for confidentiality + integrity
* Password-based key derivation using PBKDF2 (SHA-256, 100k iterations)
* Secure random salt + nonce generation
* Clean and simple Tkinter GUI
* Ensures file authenticity with GCM authentication tag
* No dependencies on external tools

---

## 📦 Tech Stack

* **Python 3.x**
* **Tkinter** (GUI)
* **cryptography** library (AES-GCM, PBKDF2)

---

## 🚀 How It Works

When encrypting:

1. Random **salt** (16 bytes) and **nonce** (12 bytes) are generated.
2. PBKDF2 derives a 256-bit AES key from the password.
3. AES-GCM encrypts the file and produces:

   * ciphertext
   * authentication tag
4. Encrypted file is saved as:

```
[salt][nonce][tag][ciphertext]
```

Decryption reverses this process using the same password.

---

## 📁 Installation

### Install Dependencies

```
pip install cryptography
```

Tkinter is included with most Python installations.
On Linux, if missing:

```
sudo apt install python3-tk
```

---

## ▶️ Run the Application

```
python file_encryptor.py
```

The GUI will open and allow you to:

* Select a file
* Enter a password
* Encrypt or decrypt with one click

---

## 🖼️ GUI Overview

* **Select File** – choose the file to encrypt or decrypt
* **Password Field** – enter the encryption/decryption password
* **Encrypt Button** – saves encrypted file as `filename.ext.enc`
* **Decrypt Button** – restores original file

---

## 📂 File Output Naming

* Encrypted files → `originalname.ext.enc`
* Decrypted files → `originalname.ext`
  If `.enc` is not found, a `.dec` file is created to avoid overwriting.

---

## ⚠️ Important Notes

* If the wrong password is used during decryption, authentication fails and the app reports:

  ```
  Invalid password or corrupted file.
  ```
* Passwords are **not recoverable**. If lost, encrypted data cannot be restored.
* AES-GCM ensures both confidentiality and tamper detection.

---

## 🛡️ Security Summary

* **AES-256-GCM**: modern authenticated encryption
* **PBKDF2 + SHA-256**: brute-force resistant key derivation
* **Random salt and nonce**: unique encryption each time
* **Authentication tag**: prevents tampering & corrupted data

---

## 📜 License

This project is licensed under the MIT License.
You may modify and distribute it freely.

---

## 🤝 Contributions

Pull requests and improvements are welcome.

---

If you'd like, I can also generate:

* A GitHub description
* A project logo
* Screenshots added into README
* A full documentation site

Just tell me what you need.
