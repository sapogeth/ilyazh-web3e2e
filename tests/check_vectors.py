# tests/check_vectors.py
import json
import base64
import sys
sys.path.append('src') 
from protocol import IlyazhProtocol
from demo_messaging import demo_handshake

def run_tests():
    print("=== Running Tests ===")

    # Full End-to-End Test
    print("Test 1: Full handshake and messaging cycle.")
    alice, bob, session_id = demo_handshake()
    
    if not alice or not bob or not session_id:
        print("❌ Test failed: Handshake was unsuccessful.")
        return

    message1 = b"Hello, Web3! This is a test."
    aad1 = b"context=test_run"
    
    print("- Alice encrypts and sends a message...")
    try:
        payload1 = alice.encrypt_message(session_id, message1, aad1)
    except Exception as e:
        print(f"❌ Test failed: Encryption error: {e}")
        return

    print("- Bob decrypts the message...")
    try:
        decrypted_text = bob.decrypt_message(payload1, aad1)
        assert message1 == decrypted_text
        print("✅ Test passed: Plaintext matches the decrypted text.")
    except Exception as e:
        print(f"❌ Test failed: Decryption error: {e}")
        return

    # Tampering test
    print("  Test 2: Verifying protection against tampering (A.A.D.).")
    try:
        tampered_aad = b"tampered_aad"
        bob.decrypt_message(payload1, tampered_aad)
        print("❌ Test failed: Tampered AAD was not rejected.")
    except ValueError as e:
        print(f"✅ Test passed: Tampered AAD was correctly rejected ({e}).")

    try:
        tampered_payload = payload1[:-10] + b'TAMPEREDDD'
        bob.decrypt_message(tampered_payload, aad1)
        print("❌ Test failed: Tampered ciphertext was decrypted.")
    except ValueError as e:
        print(f"✅ Test passed: Tampered ciphertext was correctly rejected ({e}).")

if __name__ == "__main__":
    run_tests()