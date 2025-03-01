import os
import base64
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

def encrypt_file_aes_gcm(file_data):
    try:
        key = os.urandom(32)  # AES-256 key (32 bytes)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        start_time = time.perf_counter()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        encryption_time = time.perf_counter() - start_time
        execution_time_enc = time.perf_counter() - start_time
        throughput = (len(file_data) / encryption_time) / (1024 * 1024) if encryption_time > 0 else 0

        return {
            "encrypted_data": encrypted_data,
            "key": key,
            "nonce": nonce,
            "tag": encryptor.tag,
            "encryption_time": encryption_time,
            "throughput": throughput,
            "execution_time_enc": execution_time_enc
        }
    except Exception as e:
        return {"error": f"Encryption failed: {str(e)}"}

def decrypt_file_aes_gcm(encrypted_data, key, nonce, tag, execution_time_enc):
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        start_time = time.perf_counter()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decryption_time = time.perf_counter() - start_time
        execution_time_dec = time.perf_counter() - start_time
        execution_time_aes_gcm = execution_time_enc + execution_time_dec
        
        return {
            "decryption_time": decryption_time,
            "execution_time_aes_gcm": execution_time_aes_gcm,
            "decrypted_data": decrypted_data
        }
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}

if __name__ == "__main__":
    file_path = input("Enter the full path to the file: ").strip()
    file_data = read_file(file_path)
    
    if file_data:
        print(f"\nEncrypting file of size {len(file_data) / 1024:.2f} KB...")
        encryption_result = encrypt_file_aes_gcm(file_data)
        
        if "error" in encryption_result:
            print(encryption_result["error"])
        else:
            print(f"\nEncryption Successful!")
            print(f"Encryption Time: {encryption_result['encryption_time']:.6f} sec")
            print(f"Execution Time (Encryption): {encryption_result['execution_time_enc']:.6f} sec")
            print(f"Throughput: {encryption_result['throughput']:.2f} MB/sec")
            print(f"Key (Base64): {base64.b64encode(encryption_result['key']).decode()}")
            print(f"Nonce (Base64): {base64.b64encode(encryption_result['nonce']).decode()}")
            print(f"Tag (Base64): {base64.b64encode(encryption_result['tag']).decode()}")

            
            decryption_result = decrypt_file_aes_gcm(
                encryption_result['encrypted_data'],
                encryption_result['key'],
                encryption_result['nonce'],
                encryption_result['tag'],
                encryption_result['execution_time_enc']
            )
            
            if "error" in decryption_result:
                print(decryption_result["error"])
            else:
               
                print(f"Decryption Time: {decryption_result['decryption_time']:.6f} sec")
                print(f"Total Execution Time: {decryption_result['execution_time_aes_gcm']:.6f} sec")