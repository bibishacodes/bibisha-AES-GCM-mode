import os
import math
from collections import Counter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def calculate_entropy(data):
    """Calculates the Shannon entropy of the given data"""
    if len(data) == 0:
        print("Warning: Data is empty!")
        return 0.0

    byte_frequencies = Counter(data)
    total_bytes = len(data)
    entropy = 0.0
    for freq in byte_frequencies.values():
        probability = freq / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy

def aes_encrypt(file_data, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create a cipher object with AES algorithm in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding to the plaintext so that its length is a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Calculate and print the entropy of the plaintext (original file data)
    plaintext_entropy = calculate_entropy(file_data)
    print(f"Plaintext entropy before encryption: {plaintext_entropy:.10f} bits per byte")

    # Encrypt the padded plaintext
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    # Calculate and print the entropy of the ciphertext
    ciphertext_entropy = calculate_entropy(cipher_text)
    print(f"Ciphertext entropy after encryption: {ciphertext_entropy:.10f} bits per byte")
    
    return iv, cipher_text

def read_file(file_path):
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print("Error: File not found!")
        return None
    except OSError as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    # Generate a random 16-byte key for AES
    key = os.urandom(16)

    # Get file input from the user
    file_path = input("Enter the full path to the file: ").strip()

    # Read the file
    file_data = read_file(file_path)

    if file_data:
        file_size = len(file_data)
        print(f"\nTesting with file of size {file_size / 1024:.2f} KB")

        # Encrypt the data and print the entropy values
        iv, cipher_text = aes_encrypt(file_data, key)
