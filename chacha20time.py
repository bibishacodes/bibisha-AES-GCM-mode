from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os
import base64
import time

def encrypt_file_chacha20(file_path):
    try:
        # Read the file
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Generate random key and nonce
        key = os.urandom(32)  # 32-byte key for ChaCha20
        nonce = os.urandom(16)  # 16-byte nonce for ChaCha20

        # Setup the ChaCha20 cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()

        # Measure encryption time
        start_time = time.perf_counter()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        end_time = time.perf_counter()

        # Calculate encryption time and throughput
        encryption_time = end_time - start_time
        throughput = len(file_data) / encryption_time / (1024 * 1024) if encryption_time > 0 else 0  # MB per second

        global execution_time_enc
        execution_time_enc = time.perf_counter() - start_time

        # Return encrypted data, key, nonce, encryption time, and throughput in Base64 format
        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "key": base64.b64encode(key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encryption_time": encryption_time,
            "throughput": throughput  # MB per second
        }
    except Exception as e:
        return {"error": f"Encryption failed: {str(e)}"}

def decrypt_file_chacha20(encrypted_data_b64, key_b64, nonce_b64):
    try:
        # Decode Base64 values
        encrypted_data = base64.b64decode(encrypted_data_b64)
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)

        # Setup the ChaCha20 cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()

        # Measure decryption time
        start_time = time.perf_counter()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        end_time = time.perf_counter()

        # Calculate decryption time
        decryption_time = end_time - start_time
        execution_time_dec = time.perf_counter() - start_time
        execution_time_chacha20 = execution_time_enc + execution_time_dec

        # Return decrypted data and decryption time
        return {
            "decrypted_data": decrypted_data,
            "decryption_time": decryption_time,
            "execution_time": execution_time_chacha20
        }
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}

# Prompt the user for a file path
file_path = input("Enter the path to the file you want to encrypt: ")

# Encrypt the file
result = encrypt_file_chacha20(file_path)

# Display the results
if "error" in result:
    print(result["error"])
else:
    print(f"Key (Base64): {result['key']}")
    print(f"Nonce (Base64): {result['nonce']}")
    print(f"Encryption Time: {result['encryption_time']:.6f} seconds")
    print(f"Throughput: {result['throughput']:.5f} MB per second")

    # Decrypt the file
    decrypt_result = decrypt_file_chacha20(result["encrypted_data"], result["key"], result["nonce"])

    if "error" in decrypt_result:
        print(decrypt_result["error"])
    else:
        print(f"Decryption Time: {decrypt_result['decryption_time']:.6f} seconds")
        print(f"Execution Time: {decrypt_result['execution_time']:.6f} seconds")
