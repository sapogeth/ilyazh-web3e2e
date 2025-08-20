# src/encrypt.py
import argparse
import sys
import oqs

sys.path.append('src')
from protocol import IlyazhProtocol
import cbor2
import os

def main():
    parser = argparse.ArgumentParser(description="Encrypt a message using Ilyazh-Web3E2E.")
    parser.add_argument("--session-file", required=True, help="Path to the session state file (e.g., alice_session.cbor).")
    parser.add_argument("--in", dest="infile", required=True, help="Path to the input plaintext file.")
    parser.add_argument("--out", required=True, help="Path to save the output ciphertext payload.")
    parser.add_argument("--aad", help="Path to the associated data file.")
    
    args = parser.parse_args()

    # Load session state
    try:
        with open(args.session_file, 'rb') as f:
            session_state = cbor2.loads(f.read())
        
        alice = IlyazhProtocol(identity_private=session_state['identity_private'])
        alice.sessions[session_state['session_id']] = session_state['session']
        session_id = session_state['session_id']
        
    except Exception as e:
        print(f"❌ ERROR: Failed to load session from file. Please ensure a session is established first. {e}")
        return

    with open(args.infile, 'rb') as f:
        plaintext = f.read()
        
    aad = b''
    if args.aad:
        with open(args.aad, 'rb') as f:
            aad = f.read()

    try:
        ciphertext_payload = alice.encrypt_message(session_id, plaintext, aad)
    except ValueError as e:
        print(f"❌ ERROR: Encryption failed - {e}")
        return
    
    with open(args.out, 'wb') as f:
        f.write(ciphertext_payload)
        
    print(f"✅ Message encrypted successfully.")
    print(f"Ciphertext payload saved to: {args.out}")

if __name__ == "__main__":
    main()