
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def xor_bytes(a, b):
    """Returns the number of differing bits between two byte sequences."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def pad_data(data):
    """Applies PKCS7 padding to the data to meet AES block size requirements."""
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
    return padder.update(data) + padder.finalize()

def compute_avalanche_effect(original_text, modified_text, key, iv):
    """Computes the avalanche effect between two AES CBC encrypted texts."""
    backend = default_backend()
    
    # Encrypt the original text
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    original_ciphertext = encryptor.update(original_text) + encryptor.finalize()
    
    # Encrypt the modified text using the same IV for isolation of the input change
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
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

# Parameters
BLOCK_SIZE = 16  # AES block size in bytes (128 bits)
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

# Apply PKCS7 padding
original_plaintext = pad_data(original_plaintext)

# Flipping a single bit in the plaintext
modified_plaintext = bytearray(original_plaintext)
modified_plaintext[0] ^= 0b00000001  # Flip the least significant bit of the first byte

modified_plaintext = bytes(modified_plaintext)

# Generate a common IV for both encryptions to isolate the effect of the plaintext change
#iv = secrets.token_bytes(16)  # Initialization vector (IV)
iv = b'\x00' * 16  # Fixed IV (for fair testing)


# Compute Avalanche Effect
avalanche_percentage, original_ciphertext, modified_ciphertext = compute_avalanche_effect(
    original_plaintext, modified_plaintext, key, iv
)

print(f"Avalanche Effect: {avalanche_percentage:.2f}% bit difference")

