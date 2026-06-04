AES-GCM Encryption Mode (JavaScript Implementation)

This project demonstrates AES-GCM (Galois/Counter Mode) encryption and decryption using modern JavaScript Web Crypto API concepts. AES-GCM is an Authenticated Encryption with Associated Data (AEAD) mode that ensures both confidentiality and integrity of data.

 What is AES-GCM?
 
AES-GCM is a secure encryption mode that:
Encrypts data (confidentiality)
Verifies data integrity (authentication)
Protects against tampering
Is widely used in modern security systems like HTTPS/TLS

Unlike older modes (like CBC), AES-GCM provides encryption + authentication in a single step.

⚙️ Features

AES-GCM encryption and decryption
Secure random IV (Initialization Vector) generation
Key-based encryption using Web Crypto API
Integrity verification using authentication tags
Lightweight and beginner-friendly implementation
🧠 How It Works

AES-GCM uses:

🔑 Secret Key – used for encryption/decryption
🎲 IV (Initialization Vector) – must be unique for every encryption
🔏 Authentication Tag – ensures data is not tampered with

Flow:

Generate a secret key
Create a random IV
Encrypt plaintext → ciphertext + auth tag
Decrypt using same key + IV
Verify integrity automatically
🚀 Getting Started
1. Clone the repository
git clone https://github.com/bibishacodes/bibisha-AES-GCM-mode.git
cd bibisha-AES-GCM-mode
2. Run the project

If it is a frontend project:

open index.html

Or run using Live Server (VS Code recommended).


Important Notes

Never reuse the same IV with the same key
Keep encryption keys secure
AES-GCM is secure only when used correctly
This project is for learning and demonstration purposes

 Concepts Used
 
AES (Advanced Encryption Standard)
GCM (Galois/Counter Mode)
Web Crypto API
Symmetric Encryption
Authentication Tags

Learning Outcome

After exploring this project, you will understand:
How AES-GCM works internally
Why authentication matters in encryption
How modern browsers handle cryptography
Secure encryption practices in JavaScript

📄 License

This project is for educational purposes. You may modify and extend it freely.

