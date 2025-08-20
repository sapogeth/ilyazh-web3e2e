# src/decrypt.py
import argparse
import sys
import oqs

sys.path.append('src')
from protocol import IlyazhProtocol
import cbor2
import os

def main():
    parser = argparse.ArgumentParser(description="Decrypt a message using Ilyazh-Web3E2E.")
    parser.add_argument("--session-file", required=True, help="Path to the session state file (e.g., bob_session.cbor).")
    parser.add_argument("--in", dest="infile", required=True, help="Path to the input ciphertext payload.")
    parser.add_argument("--out", required=True, help="Path to save the decrypted plaintext file.")
    parser.add_argument("--aad", help="Path to the associated data file.")
    args = parser.parse_args()

    # Load session state
    try:
        with open(args.session_file, 'rb') as f:
            session_state = cbor2.loads(f.read())
        
        bob = IlyazhProtocol(identity_private=session_state['identity_private'])
        bob.sessions[session_state['session_id']] = session_state['session']
        
    except Exception as e:
        print(f"❌ ERROR: Failed to load session from file. Please ensure a session is established first. {e}")
        return
        
    with open(args.infile, 'rb') as f:
        payload = f.read()
        
    aad = b''
    if args.aad:
        with open(args.aad, 'rb') as f:
            aad = f.read()

    try:
        plaintext = bob.decrypt_message(payload, aad)
        with open(args.out, 'wb') as f:
            f.write(plaintext)
        print(f"✅ Message decrypted successfully.")
        print(f"Plaintext saved to: {args.out}")
    except ValueError as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    main()