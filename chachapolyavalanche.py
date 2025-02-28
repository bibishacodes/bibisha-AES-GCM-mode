import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def xor_bytes(a, b):
    """Returns the number of differing bits between two byte sequences."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))




def compute_avalanche_effect(original_text, modified_text, key, nonce):
    """Computes the avalanche effect between two ChaCha20-Poly1305 encrypted texts."""
    chacha = ChaCha20Poly1305(key)

    # Encrypt original text (include the authentication tag)
    original_ciphertext = chacha.encrypt(nonce, original_text, None)

    # Encrypt modified text with the same key and nonce
    modified_ciphertext = chacha.encrypt(nonce, modified_text, None)

    # Ensure ciphertexts are of equal length
    min_length = min(len(original_ciphertext), len(modified_ciphertext))
    original_ciphertext = original_ciphertext[:min_length]
    modified_ciphertext = modified_ciphertext[:min_length]
    print("Original Ciphertext:", original_ciphertext[:64].hex())  # Print first 64 bytes
    print("Modified Ciphertext:", modified_ciphertext[:64].hex())


    # Compute differing bits
    bit_diff = xor_bytes(original_ciphertext, modified_ciphertext)
    total_bits = len(original_ciphertext) * 8
    avalanche_percentage = (bit_diff / total_bits) * 100 if total_bits > 0 else 0

    return avalanche_percentage, original_ciphertext, modified_ciphertext

def read_file_binary(file_path, chunk_size=4096):
    """Reads a file in binary mode in chunks to avoid memory overflow."""
    data = bytearray()
    with open(file_path, 'rb') as file:
        while chunk := file.read(chunk_size):
            data.extend(chunk)
    return bytes(data)

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
modified_plaintext[0] ^= 0b00000001  # Flip one bit
modified_plaintext = bytes(modified_plaintext)

# Parameters for ChaCha20-Poly1305
key = secrets.token_bytes(32)  # 256-bit key
nonce = secrets.token_bytes(12)  # 12-byte nonce (Correct size!)

# Compute Avalanche Effect
avalanche_percentage, original_ciphertext, modified_ciphertext = compute_avalanche_effect(
    original_plaintext, modified_plaintext, key, nonce
)

print(f"Avalanche Effect: {avalanche_percentage:.2f}% bit difference")
print(f"Original Ciphertext Length: {len(original_ciphertext)}")
print(f"Modified Ciphertext Length: {len(modified_ciphertext)}")
