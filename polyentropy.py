import os
import math
from collections import Counter
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def calculate_entropy(data):
    """Calculates the Shannon entropy of the given data"""
    if len(data) == 0:
        print("Warning: Data is empty!")
        return 0.0

    byte_frequencies = Counter(data)
    total_bytes = len(data)
    entropy = -sum((freq / total_bytes) * math.log2(freq / total_bytes) for freq in byte_frequencies.values())
    
    return entropy

def chacha20_poly1305_encrypt(file_data, key, nonce):
    # Create a ChaCha20-Poly1305 cipher object
    cipher = ChaCha20Poly1305(key)
    
    # Additional authenticated data (AAD) - can be empty
    aad = None
    
    # Calculate entropy of plaintext
    plaintext_entropy = calculate_entropy(file_data)
    print(f"Plaintext entropy before encryption: {plaintext_entropy:.10f} bits per byte")
    
    # Encrypt the data with authentication
    cipher_text = cipher.encrypt(nonce, file_data, aad)
    
    # Calculate entropy of ciphertext
    ciphertext_entropy = calculate_entropy(cipher_text)
    print(f"Ciphertext entropy after encryption: {ciphertext_entropy:.10f} bits per byte")
    
    return cipher_text

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
    # Generate a random 32-byte key for ChaCha20-Poly1305
    key = os.urandom(32)
    nonce = os.urandom(12)  # ChaCha20-Poly1305 requires a 12-byte nonce

    # Get file input from user
    file_path = input("Enter the full path to the file: ").strip()

    # Read file
    file_data = read_file(file_path)

    if file_data:
        file_size = len(file_data)  # Get size in bytes
        print(f"\nTesting with file of size {file_size / 1024:.2f} KB")

        # Encrypt the data and print entropy values
        cipher_text = chacha20_poly1305_encrypt(file_data, key, nonce)
