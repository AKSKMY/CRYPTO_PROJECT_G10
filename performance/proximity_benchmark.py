import time
import json
import os
import sqlite3
from algorithms.paillier_proximity import paillier
from algorithms.encryption_utils import encrypt_message, decrypt_message
from algorithms.rsa_private_auth import verify_signature

DB_PATH = "proximity.db"

def measure_execution_time(func, *args, **kwargs):
    """Helper function to measure execution time of any function."""
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
    return result, execution_time

def update_location_performance(user_id, x, y):
    """Measure the time taken to encrypt and store user location."""
    encrypted_x, encrypt_time_x = measure_execution_time(paillier.encrypt, x)
    encrypted_y, encrypt_time_y = measure_execution_time(paillier.encrypt, y)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO locations (user_id, x, y) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET x=?, y=?",
        (user_id, encrypted_x, encrypted_y, encrypted_x, encrypted_y)
    )
    conn.commit()
    conn.close()

    total_time = encrypt_time_x + encrypt_time_y
    return total_time

def check_proximity_performance(user_id):
    """Measure the time taken to check proximity."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT x, y FROM locations WHERE user_id=?", (user_id,))
    user_location = cursor.fetchone()

    if not user_location:
        return None, "User location not found"

    encrypted_x, encrypted_y = user_location
    start_time = time.time()

    # Find nearby users
    cursor.execute("SELECT user_id, x, y FROM locations WHERE user_id != ?", (user_id,))
    for other_user_id, enc_x, enc_y in cursor.fetchall():
        decrypted_x = paillier.decrypt(enc_x)
        decrypted_y = paillier.decrypt(enc_y)

        distance_squared = (decrypted_x - paillier.decrypt(encrypted_x))**2 + \
                           (decrypted_y - paillier.decrypt(encrypted_y))**2

        if distance_squared < 1000000:  # 1000x1000 proximity grid
            pass  # Simulating the check

    end_time = time.time()
    conn.close()
    return (end_time - start_time) * 1000  # Convert to milliseconds

def send_message_performance(sender_id, recipient_id, message):
    """Measure the time taken to verify proximity and send an encrypted message."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT x, y FROM locations WHERE user_id=?", (sender_id,))
    sender_location = cursor.fetchone()
    cursor.execute("SELECT x, y FROM locations WHERE user_id=?", (recipient_id,))
    recipient_location = cursor.fetchone()

    if not sender_location or not recipient_location:
        return None, "Location not set"

    sender_grid = (paillier.decrypt(sender_location[0]) // 1000, paillier.decrypt(sender_location[1]) // 1000)
    recipient_grid = (paillier.decrypt(recipient_location[0]) // 1000, paillier.decrypt(recipient_location[1]) // 1000)

    start_time = time.time()
    if sender_grid == recipient_grid:
        encrypted_message = encrypt_message(message)  # Simulating encryption process
        cursor.execute(
            "INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)",
            (sender_id, recipient_id, encrypted_message)
        )
        conn.commit()
    end_time = time.time()

    conn.close()
    return (end_time - start_time) * 1000  # Convert to milliseconds

def signature_verification_performance(public_key, message, signature):
    """Measure the time taken to verify a digital signature."""
    _, exec_time = measure_execution_time(verify_signature, public_key, message, signature)
    return exec_time

def run_performance_tests():
    """Execute and log all performance tests."""
    print("\n=== Performance Evaluation: CPU Overhead of Proximity Protocol ===\n")

    # Simulated user ID and coordinates
    user_id = 1
    x, y = 12345, 67890
    recipient_id = 2
    test_message = "Hello, this is a proximity test message."

    # Measure location update time
    location_time = update_location_performance(user_id, x, y)
    print(f"🔹 Location Update Time: {location_time:.3f} ms")

    # Measure proximity check time
    proximity_time = check_proximity_performance(user_id)
    print(f"🔹 Proximity Check Time: {proximity_time:.3f} ms")

    # Measure message sending time
    message_time = send_message_performance(user_id, recipient_id, test_message)
    print(f"🔹 Message Sending Time (with proximity check): {message_time:.3f} ms")

    # Measure signature verification time (simulated)
    sample_signature = "abcd1234"  # Replace with actual signature test
    public_key = "fake_public_key"  # Replace with actual key
    signature_time = signature_verification_performance(public_key, test_message, sample_signature)
    print(f"🔹 Signature Verification Time: {signature_time:.3f} ms")

if __name__ == "__main__":
    run_performance_tests()
