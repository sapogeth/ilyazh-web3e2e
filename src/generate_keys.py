# src/generate_keys.py
import sys
import os
import cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from protocol import IlyazhProtocol

def main():
    """
    Generates and saves identity keys for a participant
    """
    print("=== Identity Key Generation ===")
    
    # Create a protocol instance for key generation
    protocol = IlyazhProtocol()
    
    identity_public = protocol.get_identity_public_bytes()
    identity_private = protocol.identity_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    print(f"✅ Identity keys generated successfully!")
    print(f"   Public Key (Identity_PK): {identity_public.hex()[:16]}...")
    print(f"   Private Key (Identity_SK): {identity_private.hex()[:16]}...")

    # In a real application, the private key should not be saved
    # in plaintext to a file.
    with open('identity_public.bin', 'wb') as f:
        f.write(identity_public)
        
    with open('identity_private.bin', 'wb') as f:
        f.write(identity_private)

if __name__ == "__main__":
    main()
