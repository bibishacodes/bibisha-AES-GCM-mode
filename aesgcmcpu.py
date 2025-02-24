import os
import time
import psutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Pin process to CPU core 0 for better consistency
p = psutil.Process(os.getpid())
p.cpu_affinity([0])  # Set CPU affinity to core 0

# Set process to high priority to minimize interruptions
p.nice(psutil.HIGH_PRIORITY_CLASS)

def get_cpu_frequency():
    """Returns the current CPU frequency in Hz."""
    freq = psutil.cpu_freq().current  # CPU frequency in MHz
    return freq * 1e6  # Convert MHz to Hz

def get_cpu_cycles(start_time_ns, end_time_ns):
    """Estimates CPU cycles from elapsed time in nanoseconds."""
    cpu_freq = get_cpu_frequency()  # Get CPU frequency in Hz
    elapsed_time_sec = (end_time_ns - start_time_ns) / 1e9  # Convert ns to sec
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
    """Performs AES encryption in GCM mode  and measures CPU cycles."""
    nonce = os.urandom(12)  # GCM mode standard nonce size is 12 bytes
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    start_time = time.perf_counter_ns()  # Start timing
    cipher_text = encryptor.update(file_data) + encryptor.finalize()
    end_time = time.perf_counter_ns()  # End timing

    cpu_cycles_used = get_cpu_cycles(start_time, end_time)
    return nonce, cipher_text, cpu_cycles_used

if __name__ == "__main__":
    key = os.urandom(16)  # Generate a random AES key (128-bit)
    file_path = input("Enter the full path to the file: ").strip()
    file_data = read_file(file_path)

    if file_data:
        file_size = len(file_data)
        print(f"\nEncrypting file of size {file_size / (1024 * 1024):.2f} MB...\n")

        num_runs = 5  # Number of iterations for averaging
        total_cycles = 0

        for i in range(num_runs):
            nonce, cipher_text, cpu_cycles = aes_encrypt_gcm(file_data, key)
            total_cycles += cpu_cycles
            #print(f"Run {i + 1}: CPU Cycles used = {cpu_cycles / 1e6:.2f} million")

        avg_cycles = total_cycles / num_runs  # Compute average cycles
        print(f"\nAverage CPU Cycles for AES encryption (GCM mode): {avg_cycles / 1e6:.2f} million cycles")
