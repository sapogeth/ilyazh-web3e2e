# src/protocol.py

import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import oqs

# --- Криптографические функции протокола Ilyazh-Web3E2E ---

def generate_kyber_keys():
    """Генерирует пару ключей Kyber-768 с помощью liboqs."""
    kem = oqs.KeyEncapsulation("Kyber-768")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return secret_key, public_key

def derive_keys_hkdf(shared_secret: bytes, salt: bytes) -> bytes:
    """Формирует ключ AES-256 из общего секрета с помощью HKDF."""
    hkdf = Hkdf(salt, shared_secret)
    # 32 байта для ключа AES-256
    return hkdf.expand(b"aes-256-gcm-key", 32)

def encrypt(recipient_pk: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Полный цикл гибридного шифрования: Kyber -> HKDF -> AES-GCM."""
    # Шаг 1: Инкапсуляция ключа (Kyber)
    ciphertext_kyber, shared_secret = Kyber768.enc(recipient_pk)
    
    # Шаг 2: Формирование ключа (HKDF)
    salt = get_random_bytes(16)
    aes_key = derive_keys_hkdf(shared_secret, salt)
    
    # Шаг 3: Аутентифицированное шифрование (AES-GCM)
    nonce = get_random_bytes(12)  # 96 бит, стандарт для GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    ciphertext_aes, auth_tag = cipher.encrypt_and_digest(plaintext)
    
    # Шаг 4: Упаковка всех компонентов в JSON, а затем в Base64
    payload = {
        "kyber_ct": base64.b64encode(ciphertext_kyber).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "aes_ct": base64.b64encode(ciphertext_aes).decode('utf-8'),
        "auth_tag": base64.b64encode(auth_tag).decode('utf-8'),
    }
    
    return json.dumps(payload).encode('utf-8')

def decrypt(recipient_sk: bytes, payload: bytes, associated_data: bytes) -> bytes:
    """Полный цикл гибридного дешифрования."""
    # Шаг 1: Распаковка payload
    try:
        payload_dict = json.loads(payload.decode('utf-8'))
        ciphertext_kyber = base64.b64decode(payload_dict["kyber_ct"])
        salt = base64.b64decode(payload_dict["salt"])
        nonce = base64.b64decode(payload_dict["nonce"])
        ciphertext_aes = base64.b64decode(payload_dict["aes_ct"])
        auth_tag = base64.b64decode(payload_dict["auth_tag"])
    except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
        raise ValueError(f"Invalid payload format: {e}")

    # Шаг 2: Декапсуляция для получения общего секрета (Kyber)
    shared_secret = Kyber768.dec(recipient_sk, ciphertext_kyber)
    
    # Шаг 3: Повторное формирование ключа (HKDF)
    aes_key = derive_keys_hkdf(shared_secret, salt)
    
    # Шаг 4: Проверка целостности и дешифрование (AES-GCM)
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext_aes, auth_tag)
        return plaintext
    except ValueError:
        raise ValueError("Decryption failed: Message has been tampered with or is corrupt.")