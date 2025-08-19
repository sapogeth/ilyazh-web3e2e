# tests/check_vectors.py

import json
import base64
import sys
# Добавляем src в путь, чтобы импортировать protocol.py
sys.path.append('../src') 
from protocol import encrypt, decrypt

def run_tests():
    print("Running tests...")
    # Генерируем тестовые данные для примера, так как они случайны
    from protocol import generate_kyber_keys
    sk, pk = generate_kyber_keys()
    plaintext = b"Hello, Web3! This is a test."
    aad = b"context=test_run"
    
    print("  Encrypting message...")
    payload = encrypt(pk, plaintext, aad)
    
    print("  Decrypting message...")
    decrypted_text = decrypt(sk, payload, aad)
    
    assert plaintext == decrypted_text
    print("✅ Test Passed: Plaintext matches decrypted text.")
    
    # Симуляция атаки
    try:
        tampered_payload = payload[:-10] + b'TAMPEREDDD'
        decrypt(sk, tampered_payload, aad)
        # Если мы дошли сюда, тест провален
        print("❌ Test Failed: Tampered message was decrypted.")
    except ValueError:
        print("✅ Test Passed: Tampered message was correctly rejected.")

if __name__ == "__main__":
    run_tests()