# src/encrypt.py

import argparse
from protocol import encrypt

def main():
    parser = argparse.ArgumentParser(description="Encrypt a message using Ilyazh-Web3E2E.")
    parser.add_argument("--peer-pk", required=True, help="Path to the recipient's public key.")
    parser.add_argument("--in", dest="infile", required=True, help="Path to the input plaintext file.")
    parser.add_argument("--out", required=True, help="Path to save the output ciphertext payload.")
    parser.add_argument("--aad", required=True, help="Path to the associated data file.")
    args = parser.parse_args()

    with open(args.peer_pk, 'rb') as f:
        recipient_pk = f.read()
        
    with open(args.infile, 'rb') as f:
        plaintext = f.read()
        
    with open(args.aad, 'rb') as f:
        aad = f.read()

    ciphertext_payload = encrypt(recipient_pk, plaintext, aad)
    
    with open(args.out, 'wb') as f:
        f.write(ciphertext_payload)
        
    print(f"✅ Message encrypted successfully.")
    print(f"   Ciphertext payload saved to: {args.out}")

if __name__ == "__main__":
    main()