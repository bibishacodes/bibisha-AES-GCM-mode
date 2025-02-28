import os
import secrets
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

def xor_bytes(a, b):
    """Returns the number of differing bits between two byte sequences."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def compute_avalanche_effect(original_text, modified_text, key, nonce):
    """Computes the avalanche effect between two ChaCha20 encrypted texts."""
    backend = default_backend()
    
    # Encrypt the original text
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    encryptor = cipher.encryptor()
    original_ciphertext = encryptor.update(original_text) + encryptor.finalize()
    
    # Encrypt the modified text using the same key and nonce to isolate the effect of the plaintext change
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    encryptor = cipher.encryptor()
    modified_ciphertext = encryptor.update(modified_text) + encryptor.finalize()

    # Compute differing bits
    bit_diff = xor_bytes(original_ciphertext, modified_ciphertext)
    total_bits = len(original_ciphertext) * 8
    avalanche_percentage = (bit_diff / total_bits) * 100

    return avalanche_percentage, original_ciphertext, modified_ciphertext

def read_file_binary(file_path, chunk_size=4096):
    """Reads a file in binary mode in chunks to avoid memory overflow."""
    data = bytearray()
    with open(file_path, 'rb') as file:
        while chunk := file.read(chunk_size):
            data.extend(chunk)
    return bytes(data)

def write_binary_file(file_path, data):
    """Writes binary data to a file."""
    with open(file_path, 'wb') as file:
        file.write(data)

# File input with error handling
try:
    file_path = input("Enter the path to the file: ")
    original_plaintext = read_file_binary(file_path)
except FileNotFoundError:
    print("Error: File not found. Please check the path.")
    exit()
except Exception as e:
    print(f"Unexpected error: {e}")
    exit()



# Flip a single bit in the plaintext (e.g., flip the least significant bit of the first byte)
modified_plaintext = bytearray(original_plaintext)
modified_plaintext[0] ^= 0b00000001  # Flip one bit
modified_plaintext = bytes(modified_plaintext)

# Parameters for ChaCha20
key = secrets.token_bytes(32)    # ChaCha20 uses a 256-bit key
nonce = secrets.token_bytes(16)  # 16-byte nonce

# Compute Avalanche Effect
avalanche_percentage, original_ciphertext, modified_ciphertext = compute_avalanche_effect(
    original_plaintext, modified_plaintext, key, nonce
)

print(f"Avalanche Effect: {avalanche_percentage:.2f}% bit difference")

