# src/generate_keys.py

import argparse
from protocol import generate_kyber_keys

def main():
    parser = argparse.ArgumentParser(description="Generate a Kyber-768 key pair.")
    parser.add_argument("--pub", required=True, help="Path to save the public key.")
    parser.add_argument("--sec", required=True, help="Path to save the secret key.")
    args = parser.parse_args()

    sk, pk = generate_kyber_keys()

    with open(args.pub, 'wb') as f:
        f.write(pk)
    
    with open(args.sec, 'wb') as f:
        f.write(sk)
        
    print(f"✅ Key pair generated successfully!")
    print(f"   Public key saved to: {args.pub}")
    print(f"   Secret key saved to: {args.sec}")

if __name__ == "__main__":
    main()