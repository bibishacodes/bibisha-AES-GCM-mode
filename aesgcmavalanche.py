import os
import secrets
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def xor_bytes(a, b):
    """Returns the number of differing bits between two byte sequences."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def compute_avalanche_effect_gcm(original_text, modified_text, key):
    """Computes the avalanche effect between two AES-GCM encrypted texts."""
    backend = default_backend()

    # Generate unique nonces for each encryption
    nonce1 = secrets.token_bytes(12)  # 96-bit nonce for original encryption
    nonce2 = secrets.token_bytes(12)  # 96-bit nonce for modified encryption

    # Encrypt the original text
    cipher1 = Cipher(algorithms.AES(key), modes.GCM(nonce1), backend=backend)
    encryptor1 = cipher1.encryptor()
    original_ciphertext = encryptor1.update(original_text) + encryptor1.finalize()
    original_tag = encryptor1.tag  # Get the authentication tag

    # Encrypt the modified text with a different nonce
    cipher2 = Cipher(algorithms.AES(key), modes.GCM(nonce2), backend=backend)
    encryptor2 = cipher2.encryptor()
    modified_ciphertext = encryptor2.update(modified_text) + encryptor2.finalize()
    modified_tag = encryptor2.tag  # Get the authentication tag

    # Combine ciphertext and tags before computing bit difference
    original_output = original_ciphertext + original_tag
    modified_output = modified_ciphertext + modified_tag

    # Compute differing bits
    bit_diff = xor_bytes(original_output, modified_output)
    total_bits = len(original_output) * 8
    avalanche_percentage = (bit_diff / total_bits) * 100

    return avalanche_percentage, original_ciphertext, modified_ciphertext

def read_file_binary(file_path, chunk_size=4096):
    """Reads a file in binary mode in chunks to avoid memory overflow."""
    data = bytearray()
    with open(file_path, 'rb') as file:
        while chunk := file.read(chunk_size):
            data.extend(chunk)
    return bytes(data)

# Parameters
key = secrets.token_bytes(16)  # AES-128 key

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

# Flip a single bit in the plaintext
modified_plaintext = bytearray(original_plaintext)
modified_plaintext[0] ^= 0b00000001  # Flip the least significant bit of the first byte
modified_plaintext = bytes(modified_plaintext)

# Compute Avalanche Effect
avalanche_percentage, original_ciphertext, modified_ciphertext = compute_avalanche_effect_gcm(
    original_plaintext, modified_plaintext, key
)

print(f"Avalanche Effect: {avalanche_percentage:.2f}% bit difference")

