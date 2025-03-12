import os
import sys
import time
import statistics

import psutil  # For CPU usage
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Paillier (phe library)
from phe import paillier, generate_paillier_keypair

# ElGamal (your code)
from algorithms.elgamal import elgamal_generate_keys, elgamal_encrypt, elgamal_decrypt

# RSA signature verification (cryptography)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# AES imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

###############################################################################
# Helper: Timed operation + CPU usage
###############################################################################
def measure_operation_with_cpu(func, *args):
    """
    - Resets CPU stats (psutil.cpu_percent(interval=0.0)).
    - Runs func(*args) and measures time in ms.
    - Right after finishing, does psutil.cpu_percent(interval=0.05) 
      to get a short CPU usage snapshot.
    Returns (elapsed_ms, cpu_usage_percent, function_result).
    """
    # Discard old CPU data
    psutil.cpu_percent(interval=0.0)

    start = time.time()
    result = func(*args)
    end = time.time()

    cpu_usage = psutil.cpu_percent(interval=0.05)  # short measure
    elapsed_ms = (end - start) * 1000
    return elapsed_ms, cpu_usage, result

###############################################################################
# RSA Signature Verification
###############################################################################
def verify_signature(public_key_pem, message, signature_hex):
    """
    Verify an RSA-PSS signature. Return True if valid, else False.
    """
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

###############################################################################
# AES Helpers
###############################################################################
def aes_key_generate(key_size=256):
    """Generate a random AES key of 'key_size' bits (e.g., 256 => 32 bytes)."""
    return os.urandom(key_size // 8)

def aes_encrypt(key, data, mode="CBC"):
    """Encrypt 'data' (bytes) using AES in CBC or CTR mode."""
    iv = os.urandom(16)  # 128-bit block
    if mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        # PKCS7 padding for CBC
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return (iv, ciphertext)
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return (iv, ciphertext)
    else:
        raise ValueError("Unsupported AES mode. Use CBC or CTR.")

def aes_decrypt(key, iv, ciphertext, mode="CBC"):
    """Decrypt using AES. Must match the mode + iv from aes_encrypt."""
    if mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
        # Unpad
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plain) + unpadder.finalize()
        return plaintext
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    else:
        raise ValueError("Unsupported AES mode.")

###############################################################################
# Main Benchmark
###############################################################################
def run_benchmarks():
    print("\n=== Performance Evaluation: CPU Overhead of Proximity Protocol ===\n")
    T = 10  # number of trials for each operation

    # 1. Generate Paillier keys
    print("[INFO] Generating Paillier keys...")
    paillier_pub, paillier_priv = generate_paillier_keypair(n_length=32)
    print("[INFO] Paillier key pair generated.\n")

    # 2. Generate ElGamal keys
    print("[INFO] Generating ElGamal keys...")
    elg_keys = elgamal_generate_keys(key_size=32)
    elg_public = elg_keys['public']
    elg_private = elg_keys['private']
    print("[INFO] ElGamal keys generated.\n")

    # 3. AES key
    print("[INFO] Generating AES key (256-bit, CBC mode).")
    aes_key = aes_key_generate(256)
    data_for_aes = b"Example data for AES encryption/decryption."
    # We'll do a single encryption for decryption test
    aes_iv, aes_cipher = aes_encrypt(aes_key, data_for_aes, "CBC")
    print("[INFO] AES key generated.\n")

    # 4. RSA Sig Verify placeholders
    fake_public_key_pem = "fake_public_key"
    test_message = "Hello, crypto project!"
    sample_sig_hex = "abcd1234"

    # 5. Prepare test values
    test_value = 12345
    # We'll encrypt once for Paillier/ElGamal decryption tests
    paillier_cipher = paillier_pub.encrypt(test_value)
    elg_cipher = elgamal_encrypt(elg_public, test_value)

    # 6. We'll store results in a dictionary
    #    { "Operation": { "times": [...], "cpus": [...] } }
    #    Then compute avg, stdev, peak CPU, etc.
    results = {}

    # Helper to run T trials of an operation with CPU measurement
    def benchmark_operation(op_name, func):
        cpu_samples = []
        time_samples = []
        for _ in range(T):
            elapsed_ms, usage, _ = measure_operation_with_cpu(func)
            time_samples.append(elapsed_ms)
            cpu_samples.append(usage)
        results[op_name] = {
            "peak_cpu": max(cpu_samples),
            "avg_cpu": sum(cpu_samples) / len(cpu_samples),
            "avg_time": statistics.mean(time_samples),
            "std_time": statistics.stdev(time_samples) if T > 1 else 0.0
        }

    # Define lambdas for each operation
    do_paillier_encrypt = lambda: paillier_pub.encrypt(test_value)
    do_paillier_decrypt = lambda: paillier_priv.decrypt(paillier_cipher)
    do_elgamal_encrypt = lambda: elgamal_encrypt(elg_public, test_value)
    do_elgamal_decrypt = lambda: elgamal_decrypt(elg_public, elg_private, elg_cipher)
    do_rsa_verify = lambda: verify_signature(fake_public_key_pem, test_message, sample_sig_hex)
    do_aes_encrypt = lambda: aes_encrypt(aes_key, data_for_aes, "CBC")
    do_aes_decrypt = lambda: aes_decrypt(aes_key, aes_iv, aes_cipher, "CBC")

    # 7. Perform the benchmarks
    print("[INFO] Benchmarking Paillier encryption...")
    benchmark_operation("Paillier Encrypt", do_paillier_encrypt)

    print("[INFO] Benchmarking Paillier decryption...")
    benchmark_operation("Paillier Decrypt", do_paillier_decrypt)

    print("[INFO] Benchmarking ElGamal encryption...")
    benchmark_operation("ElGamal Encrypt", do_elgamal_encrypt)

    print("[INFO] Benchmarking ElGamal decryption...")
    benchmark_operation("ElGamal Decrypt", do_elgamal_decrypt)

    print("[INFO] Benchmarking RSA signature verification...")
    benchmark_operation("RSA Sig Verify", do_rsa_verify)

    print("[INFO] Benchmarking AES encryption (CBC)...")
    benchmark_operation("AES Encrypt", do_aes_encrypt)

    print("[INFO] Benchmarking AES decryption (CBC)...")
    benchmark_operation("AES Decrypt", do_aes_decrypt)

    # 8. Print CPU usage table
    print("\n🔎 CPU Usage Statistics by Algorithm:\n")
    print("=" * 55)
    print(f"{'Operation':<20}{'Peak CPU (%)':>15}{'Avg CPU (%)':>15}")
    print("=" * 55)
    for op_name in [
        "Paillier Encrypt", "Paillier Decrypt", 
        "ElGamal Encrypt", "ElGamal Decrypt", 
        "AES Encrypt", "AES Decrypt"
    ]:
        peak = results[op_name]["peak_cpu"]
        avg = results[op_name]["avg_cpu"]
        print(f"{op_name:<20}{peak:>15.2f}{avg:>15.2f}")
    print("=" * 55)

    # 9. Print normal benchmark results (time in ms)
    print(f"\n📊 Benchmark Results ({T} trials per test)\n")
    print("=" * 65)
    print(f"{'Operation':<20}{'Avg (ms)':>15}{'Std Dev (ms)':>15}")
    print("=" * 65)
    for op_name in [
        "Paillier Encrypt", "Paillier Decrypt", 
        "ElGamal Encrypt", "ElGamal Decrypt", 
        "RSA Sig Verify", "AES Encrypt", "AES Decrypt"
    ]:
        info = results[op_name]
        print(f"{op_name:<20}{info['avg_time']:>15.3f}{info['std_time']:>15.3f}")
    print("=" * 65)


if __name__ == "__main__":
    run_benchmarks()
