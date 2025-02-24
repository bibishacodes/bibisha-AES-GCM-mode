import os
import time
import psutil
import gc
import statistics
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def encrypt_decrypt_aes_gcm(file_path, key_size_bits=128, iterations=2):
    file_size = os.path.getsize(file_path)
    print(f"File size: {file_size / (1024*1024):.2f} MB")

    key = os.urandom(key_size_bits // 8)
    nonce = os.urandom(12)  # GCM recommended nonce size

    encr_times = []
    decr_times = []
    total_exec_times = []
    encr_throughputs = []
    decr_throughputs = []
    total_exec_throughputs = []

    gc.disable()  # Disable garbage collection before timing

    for _ in range(iterations):
        start_exec_time = time.perf_counter()  # Start total execution time measurement

        # Encryption
        with open(file_path, "rb") as f:
            data = f.read()

        start_encr = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        encr_time = time.perf_counter() - start_encr
        encr_throughput = (file_size / 1024 / 1024) / encr_time if encr_time > 0 else 0

        encr_times.append(encr_time)
        encr_throughputs.append(encr_throughput)

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as f:
            f.write(nonce + tag + ciphertext)

        # Decryption
        with open(encrypted_file_path, "rb") as f:
            nonce_read = f.read(12)
            tag_read = f.read(16)
            ciphertext = f.read()

        start_decr = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce_read, tag_read), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        decr_time = time.perf_counter() - start_decr
        decr_throughput = (file_size / 1024 / 1024) / decr_time if decr_time > 0 else 0

        decr_times.append(decr_time)
        decr_throughputs.append(decr_throughput)

        decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        total_exec_time = time.perf_counter() - start_exec_time  # End total execution time measurement
        total_exec_throughput = (file_size / 1024 / 1024) / total_exec_time if total_exec_time > 0 else 0

        total_exec_times.append(total_exec_time)
        total_exec_throughputs.append(total_exec_throughput)

    gc.enable()  # Enable garbage collection after timing

    # Compute standard deviations
    encr_time_sd = statistics.stdev(encr_times) if len(encr_times) > 1 else 0
    decr_time_sd = statistics.stdev(decr_times) if len(decr_times) > 1 else 0
    total_exec_time_sd = statistics.stdev(total_exec_times) if len(total_exec_times) > 1 else 0
    encr_throughput_sd = statistics.stdev(encr_throughputs) if len(encr_throughputs) > 1 else 0
    decr_throughput_sd = statistics.stdev(decr_throughputs) if len(decr_throughputs) > 1 else 0
    total_exec_throughput_sd = statistics.stdev(total_exec_throughputs) if len(total_exec_throughputs) > 1 else 0

    print("\n===== AES-GCM Encryption & Decryption Results (Averaged over iterations) =====")
    print(f"Avg Encryption Time: {statistics.mean(encr_times):.6f} ± {encr_time_sd:.6f} sec")
    print(f"Avg Encryption Throughput: {statistics.mean(encr_throughputs):.2f} ± {encr_throughput_sd:.2f} MB/s")
    print(f"Avg Decryption Time: {statistics.mean(decr_times):.6f} ± {decr_time_sd:.6f} sec")
    print(f"Avg Decryption Throughput: {statistics.mean(decr_throughputs):.2f} ± {decr_throughput_sd:.2f} MB/s")
    print(f"Avg Total Execution Time (Enc + Dec): {statistics.mean(total_exec_times):.6f} ± {total_exec_time_sd:.6f} sec")
    print(f"Avg Total Execution Throughput: {statistics.mean(total_exec_throughputs):.2f} ± {total_exec_throughput_sd:.2f} MB/s")
    print(f"Encrypted file saved as: {encrypted_file_path}")
    print(f"Decrypted file saved as: {decrypted_file_path}")

    return {
        "avg_encr_time": statistics.mean(encr_times),
        "sd_encr_time": encr_time_sd,
        "avg_decr_time": statistics.mean(decr_times),
        "sd_decr_time": decr_time_sd,
        "avg_total_exec_time": statistics.mean(total_exec_times),
        "sd_total_exec_time": total_exec_time_sd,
        "avg_encr_throughput": statistics.mean(encr_throughputs),
        "sd_encr_throughput": encr_throughput_sd,
        "avg_decr_throughput": statistics.mean(decr_throughputs),
        "sd_decr_throughput": decr_throughput_sd,
        "avg_total_exec_throughput": statistics.mean(total_exec_throughputs),
        "sd_total_exec_throughput": total_exec_throughput_sd,
        "encrypted_file_path": encrypted_file_path,
        "decrypted_file_path": decrypted_file_path
    }

# Get file path input
file_path = input("Enter the file path: ")
encrypt_decrypt_aes_gcm(file_path)
