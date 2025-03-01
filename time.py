from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time
import base64

def read_file(file_path):
    try:
        with open(file_path, "rb") as file:
            return file.read()
    except FileNotFoundError:
        print("Error: File not found!")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def encrypt_file_aes_cbc(file_data):
    try:
        start_execution = time.perf_counter()
        key = os.urandom(32)  # AES-256 key (16 bytes)
        iv = os.urandom(16)   # IV (16 bytes)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        start_time = time.perf_counter()
        pad_length = 16 - (len(file_data) % 16)
        padded_data = file_data + bytes([pad_length] * pad_length)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        encryption_time = time.perf_counter() - start_time
        
        throughput = (len(file_data) / encryption_time) / (1024 * 1024) if encryption_time > 0 else 0
        execution_time_enc = time.perf_counter() - start_execution
        
        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "key": base64.b64encode(key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "encryption_time": encryption_time,
            "throughput": throughput,
            "execution_time_enc": execution_time_enc
        }
    except Exception as e:
        return {"error": f"Encryption failed: {str(e)}"}

def decrypt_file_aes_cbc(encrypted_data_b64, key_b64, iv_b64, execution_time_enc):
    try:
        start_execution = time.perf_counter()
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        start_time = time.perf_counter()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decryption_time = time.perf_counter() - start_time
        
        execution_time_dec = time.perf_counter() - start_execution
        execution_time_aes_cbc = execution_time_enc + execution_time_dec
        
        return {
            "decryption_time": decryption_time,
            "execution_time_aes_cbc": execution_time_aes_cbc
        }
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}

if __name__ == "__main__":
    file_path = input("Enter the full path to the file: ").strip()
    file_data = read_file(file_path)
    
    if file_data:
        print(f"\nEncrypting file of size {len(file_data) / 1024:.2f} KB...")
        encrypt_result = encrypt_file_aes_cbc(file_data)
        
        if "error" in encrypt_result:
            print(encrypt_result["error"])
        else:
            decrypt_result = decrypt_file_aes_cbc(
                encrypt_result["encrypted_data"], 
                encrypt_result["key"], 
                encrypt_result["iv"],
                encrypt_result["execution_time_enc"]  # Pass execution time from encryption
            )
            
            if "error" in decrypt_result:
                print(decrypt_result["error"])
            else:
                print("\nEncryption and Decryption Successful!")
                print(f"Encryption Time: {encrypt_result['encryption_time']:.6f} sec")
                print(f"Decryption Time: {decrypt_result['decryption_time']:.6f} sec")
                print(f"Execution Time: {decrypt_result['execution_time_aes_cbc']:.6f} sec")
                print(f"Throughput: {encrypt_result['throughput']:.2f} MB/sec")
                print(f"Key (Base64): {encrypt_result['key']}")
                print(f"IV (Base64): {encrypt_result['iv']}")