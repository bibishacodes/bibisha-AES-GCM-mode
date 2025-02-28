import os
import time
import psutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Pin process to multiple CPU cores to reduce interruptions
p = psutil.Process(os.getpid())
p.cpu_affinity([0, 1])  # Use cores 0 and 1 for better consistency

# Set process to high priority
p.nice(psutil.HIGH_PRIORITY_CLASS)

def get_cpu_frequency():
    """Returns the average CPU frequency in Hz."""
    freqs = psutil.cpu_freq()
    return freqs.current * 1e6  # Convert MHz to Hz

def get_cpu_cycles(start_time_ns, end_time_ns):
    """Estimates CPU cycles based on elapsed time."""
    cpu_freq = get_cpu_frequency()
    elapsed_time_sec = (end_time_ns - start_time_ns) / 1e9
    return int(elapsed_time_sec * cpu_freq)  # CPU cycles = time * frequency

def read_file(file_path):
    """Reads a file and returns its binary content."""
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print("Error: File not found!")
        return None
    except OSError as e:
        print(f"Error: {e}")
        return None

def aes_encrypt_gcm(file_data, key):
    """Performs AES-GCM encryption and measures CPU cycles."""
    nonce = os.urandom(12)  # 12-byte IV (GCM standard)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    start_time = time.perf_counter_ns()
    cipher_text = encryptor.update(file_data) + encryptor.finalize()
    end_time = time.perf_counter_ns()

    cpu_cycles_used = get_cpu_cycles(start_time, end_time)
    return nonce, cipher_text, encryptor.tag, cpu_cycles_used  # Return tag as well

if __name__ == "__main__":
    key = os.urandom(32)  # AES-256 key
    file_path = input("Enter the full path to the file: ").strip()
    file_data = read_file(file_path)

    if file_data:
        file_size = len(file_data)
        print(f"\nEncrypting file of size {file_size / (1024 * 1024):.2f} MB...\n")

        num_runs = 10  # More runs for better averaging
        total_cycles = 0

        for i in range(num_runs):
            nonce, cipher_text, tag, cpu_cycles = aes_encrypt_gcm(file_data, key)
            
            if i > 0:  # Skip first run for better accuracy
                total_cycles += cpu_cycles

            #print(f"Run {i + 1}: CPU Cycles = {cpu_cycles / 1e6:.2f} million")

        avg_cycles = total_cycles / (num_runs - 1)  # Exclude first run
        print(f"\nFinal Average CPU Cycles: {avg_cycles / 1e6:.2f} million cycles")
