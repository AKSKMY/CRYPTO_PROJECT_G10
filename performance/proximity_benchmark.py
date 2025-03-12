import time
import os
import sys
import sqlite3
import statistics
import psutil

# Ensure Python can locate your "algorithms" package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# -- Phe Imports (Paillier) --
from phe import paillier, generate_paillier_keypair

# -- Encryption Utils --
from algorithms.encryption_utils import encrypt_message

# -- ElGamal Imports --
from algorithms.elgamal import elgamal_generate_keys, elgamal_encrypt, elgamal_decrypt

# -- Cryptography (for RSA signature verification) --
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

DB_PATH = "proximity.db"

# ---------------------------------------------------------------
# Generate a Paillier key pair
# ---------------------------------------------------------------
print("[INFO] Generating Paillier key pair (this may take time)...")
public_key, private_key = generate_paillier_keypair(n_length=32)
print("[SUCCESS] Paillier key pair generated!")


def my_encrypt(x):
    """Encrypt x using the generated Paillier public_key."""
    return public_key.encrypt(x)

def my_decrypt(encrypted_obj):
    """Decrypt encrypted_obj using the generated Paillier private_key."""
    return private_key.decrypt(encrypted_obj)

# Override the functions in the phe.paillier module
paillier.encrypt = my_encrypt
paillier.decrypt = my_decrypt

# ---------------------------------------------------------------
# Generate ElGamal keys
# ---------------------------------------------------------------
print("[INFO] Generating ElGamal key pair...")
try:
    elgamal_keys = elgamal_generate_keys(key_size=32)  # Reduce key size if too slow
    elgamal_public = elgamal_keys['public']
    elgamal_private = elgamal_keys['private']
    print("[SUCCESS] ElGamal keys generated.")
except Exception as e:
    print(f"[ERROR] Failed to generate ElGamal keys: {e}")
    sys.exit(1)

# ---------------------------------------------------------------
# Helper: measure_execution_time
# ---------------------------------------------------------------
def measure_execution_time(func, *args, **kwargs):
    """Measure execution time of a function (in ms)."""
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    return result, (end_time - start_time) * 1000

# ---------------------------------------------------------------
# RSA Signature Verification
# ---------------------------------------------------------------
def verify_signature(public_key_pem, message, signature_hex):
    """Verify a digital signature using RSA (PSS)."""
    try:
        public_key = load_pem_public_key(public_key_pem.encode())
        public_key.verify(
            bytes.fromhex(signature_hex),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------------------------------------------------------------
# Benchmark: Paillier Encryption/Decryption
# ---------------------------------------------------------------
def paillier_encryption_performance(value, trials=10):
    times = [measure_execution_time(paillier.encrypt, value)[1] for _ in range(trials)]
    return statistics.mean(times), statistics.stdev(times)

def paillier_decryption_performance(encrypted_val, trials=10):
    times = [measure_execution_time(paillier.decrypt, encrypted_val)[1] for _ in range(trials)]
    return statistics.mean(times), statistics.stdev(times)

# ---------------------------------------------------------------
# Benchmark: ElGamal Encryption/Decryption
# ---------------------------------------------------------------
def elgamal_encryption_performance(pub_key, value, trials=10):
    """Measure ElGamal encryption performance."""
    times = [measure_execution_time(elgamal_encrypt, pub_key, value)[1] for _ in range(trials)]
    return statistics.mean(times), statistics.stdev(times)

def elgamal_decryption_performance(pub_key, priv_key, ciphertext, trials=10):
    """Measure ElGamal decryption performance."""
    times = [measure_execution_time(elgamal_decrypt, pub_key, priv_key, ciphertext)[1] for _ in range(trials)]
    return statistics.mean(times), statistics.stdev(times)

# ---------------------------------------------------------------
# Benchmark: Signature Verification
# ---------------------------------------------------------------
def signature_verification_performance(pub_key_pem, message, signature_hex, trials=10):
    times = [measure_execution_time(verify_signature, pub_key_pem, message, signature_hex)[1] for _ in range(trials)]
    return statistics.mean(times), statistics.stdev(times)




# ---------------------------------------------------------------
# CPU Usage
# ---------------------------------------------------------------

def monitor_cpu_usage(duration=1):
    """Monitor CPU usage over a specified duration and return stats."""
    cpu_usages = []

    for _ in range(duration):
        cpu_usages.append(psutil.cpu_percent(interval=0.1))  # Sample every 100ms

    return {
        "avg_cpu": statistics.mean(cpu_usages),
        "peak_cpu": max(cpu_usages)
    }

def monitor_cpu_usage_for_function(func, *args, **kwargs):
    """Measure CPU usage while running a specific function."""
    cpu_usages = []
    start_time = time.time()
    
    while time.time() - start_time < 1:  # Monitor for 1 second
        cpu_usages.append(psutil.cpu_percent(interval=0.1))  # Sample every 100ms

    result = func(*args, **kwargs)  # Execute function
    return result, {
        "avg_cpu": statistics.mean(cpu_usages),
        "peak_cpu": max(cpu_usages)
    }
# ---------------------------------------------------------------
# Main Benchmark Suite
# ---------------------------------------------------------------
def run_performance_tests():
    print("\n=== Performance Evaluation: CPU Overhead of Proximity Protocol ===\n")
    
    T = 10  # Number of trials
    test_value = 12345
    test_message = "Hello, crypto project!"
    sample_signature = "abcd1234"  # Replace with real signature
    fake_public_key_pem = "fake_public_key"  # Replace with actual PEM

    print("[INFO] Running benchmarks...")

    # --- Paillier Encryption ---
    print("[INFO] Benchmarking Paillier encryption...")
    encrypted_val, paillier_enc_cpu = monitor_cpu_usage_for_function(paillier.encrypt, test_value)
    paillier_enc_mean, paillier_enc_std = paillier_encryption_performance(test_value, trials=T)

    # --- Paillier Decryption ---
    print("[INFO] Benchmarking Paillier decryption...")
    _, paillier_dec_cpu = monitor_cpu_usage_for_function(paillier.decrypt, encrypted_val)
    paillier_dec_mean, paillier_dec_std = paillier_decryption_performance(encrypted_val, trials=T)

    # --- ElGamal Encryption ---
    print("[INFO] Benchmarking ElGamal encryption...")
    encrypted_elg_val, elgamal_enc_cpu = monitor_cpu_usage_for_function(elgamal_encrypt, elgamal_public, test_value)
    elg_enc_mean, elg_enc_std = elgamal_encryption_performance(elgamal_public, test_value, trials=T)

    # --- ElGamal Decryption ---
    print("[INFO] Benchmarking ElGamal decryption...")
    _, elgamal_dec_cpu = monitor_cpu_usage_for_function(elgamal_decrypt, elgamal_public, elgamal_private, encrypted_elg_val)
    elg_dec_mean, elg_dec_std = elgamal_decryption_performance(elgamal_public, elgamal_private, encrypted_elg_val, trials=T)

    # -- 5) Signature Verification --
    print("[INFO] Benchmarking RSA signature verification...")
    sig_mean, sig_std = signature_verification_performance(fake_public_key_pem, test_message, sample_signature, trials=T)

    # --- Display Results ---
    print("\n🔍 CPU Usage Statistics by Algorithm:")
    print("=" * 60)
    print(f"{'Operation':<25}{'Peak CPU (%)':>15}{'Avg CPU (%)':>15}")
    print("=" * 60)
    print(f"{'Paillier Encrypt':<25}{paillier_enc_cpu['peak_cpu']:>15.2f}{paillier_enc_cpu['avg_cpu']:>15.2f}")
    print(f"{'Paillier Decrypt':<25}{paillier_dec_cpu['peak_cpu']:>15.2f}{paillier_dec_cpu['avg_cpu']:>15.2f}")
    print(f"{'ElGamal Encrypt':<25}{elgamal_enc_cpu['peak_cpu']:>15.2f}{elgamal_enc_cpu['avg_cpu']:>15.2f}")
    print(f"{'ElGamal Decrypt':<25}{elgamal_dec_cpu['peak_cpu']:>15.2f}{elgamal_dec_cpu['avg_cpu']:>15.2f}")
    print("=" * 60)

     # Print results
    print("\n📊 Benchmark Results ({} trials per test)".format(T))
    print("=" * 75)
    print(f"{'Operation':<30}{'Avg (ms)':>15}{'Std Dev (ms)':>15}")
    print("=" * 75)
    print(f"{'Paillier Encrypt':<30}{paillier_enc_mean:>15.3f}{paillier_enc_std:>15.3f}")
    print(f"{'Paillier Decrypt':<30}{paillier_dec_mean:>15.3f}{paillier_dec_std:>15.3f}")
    print(f"{'ElGamal Encrypt':<30}{elg_enc_mean:>15.3f}{elg_enc_std:>15.3f}")
    print(f"{'ElGamal Decrypt':<30}{elg_dec_mean:>15.3f}{elg_dec_std:>15.3f}")
    print(f"{'RSA Sig Verify':<30}{sig_mean:>15.3f}{sig_std:>15.3f}")
    print("=" * 75)

if __name__ == "__main__":
    run_performance_tests()