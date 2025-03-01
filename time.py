from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import base64
import time

def encrypt_file_chacha20_poly1305(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()

        key = os.urandom(32)  # 256-bit key for ChaCha20-Poly1305
        nonce = os.urandom(12)  # 12-byte nonce
        chacha = ChaCha20Poly1305(key)

        start_time = time.perf_counter()
        encrypted_data = chacha.encrypt(nonce, file_data, None)
        encryption_time = time.perf_counter() - start_time

        throughput = len(file_data) / encryption_time / (1024 * 1024) if encryption_time > 0 else 0  # MB per second

        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "key": base64.b64encode(key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encryption_time": encryption_time,
            "throughput": throughput  
        }
    except Exception as e:
        return {"error": f"Encryption failed: {str(e)}"}

def decrypt_file_chacha20_poly1305(encrypted_data_b64, key_b64, nonce_b64):
    try:
        encrypted_data = base64.b64decode(encrypted_data_b64)
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        chacha = ChaCha20Poly1305(key)

        start_time = time.perf_counter()
        decrypted_data = chacha.decrypt(nonce, encrypted_data, None)
        decryption_time = time.perf_counter() - start_time

        return {
            "decrypted_data": decrypted_data,
            "decryption_time": decryption_time
        }
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}

file_path = input("Enter the path to the file: ").strip()

start_execution = time.perf_counter()
result = encrypt_file_chacha20_poly1305(file_path)

if "error" in result:
    print(result["error"])
else:
    print(f"\nEncryption Successful!")
    print(f"Encryption Time: {result['encryption_time']:.6f} seconds")
    print(f"Throughput: {result['throughput']:.2f} MB per second")
    print(f"Key (Base64): {result['key']}")
    print(f"Nonce (Base64): {result['nonce']}")

    print("\nDecrypting file...")
    decryption_result = decrypt_file_chacha20_poly1305(result["encrypted_data"], result["key"], result["nonce"])

    if "error" in decryption_result:
        print(decryption_result["error"])
    else:
        
        print(f"Decryption Time: {decryption_result['decryption_time']:.6f} seconds")

execution_time = time.perf_counter() - start_execution
print(f"\nTotal Execution Time (Encryption + Decryption): {execution_time:.6f} seconds")
