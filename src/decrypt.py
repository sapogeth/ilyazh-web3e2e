# src/decrypt.py

import argparse
from protocol import decrypt

def main():
    parser = argparse.ArgumentParser(description="Decrypt a message using Ilyazh-Web3E2E.")
    parser.add_argument("--sk", required=True, help="Path to your secret key.")
    parser.add_argument("--in", dest="infile", required=True, help="Path to the input ciphertext payload.")
    parser.add_argument("--out", required=True, help="Path to save the decrypted plaintext file.")
    parser.add_argument("--aad", required=True, help="Path to the associated data file.")
    args = parser.parse_args()

    with open(args.sk, 'rb') as f:
        recipient_sk = f.read()
        
    with open(args.infile, 'rb') as f:
        payload = f.read()
        
    with open(args.aad, 'rb') as f:
        aad = f.read()

    try:
        plaintext = decrypt(recipient_sk, payload, aad)
        with open(args.out, 'wb') as f:
            f.write(plaintext)
        print(f"✅ Message decrypted successfully.")
        print(f"   Plaintext saved to: {args.out}")
    except ValueError as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    main()