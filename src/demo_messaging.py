"""
Demonstration of the full cycle: handshake and message exchange
with a preliminary check for Kyber-768 algorithm availability
"""

import os
import sys
import oqs

sys.path.append('src')
from protocol import IlyazhProtocol
import cbor2
import time

def check_kyber_support():
    """Checks if Kyber-768 is available in the installed liboqs."""
    try:
        available = oqs.get_enabled_kem_mechanisms()
        if "Kyber768" not in available:
            print("❌ Kyber768 not found. Please install it by following the instructions.")
            sys.exit(1)
        else:
            print("✅ Kyber768 found, continuing...")
    except ImportError:
        print("❌ pyoqs is not installed. Please install it.")
        sys.exit(1)


def demo_handshake():
    """
    Demonstrates Handshake and session initialization.
    """
    print("=== Ilyazh-Web3E2E Handshake Demonstration ===\n")
    
    print("1. Creating participants...")
    alice = IlyazhProtocol()
    bob = IlyazhProtocol()
    
    print("Alice identity: ", alice.get_identity_public_bytes().hex()[:16] + "...")
    print("Bob identity:   ", bob.get_identity_public_bytes().hex()[:16] + "...")
    print()
    
    print("2. Alice initiates handshake...")
    alice_handshake = alice.initiate_handshake(bob.get_identity_public_bytes())
    print("Handshake message size:", len(alice_handshake), "bytes")
    print()
    
    print("3. Bob processes handshake...")
    try:
        bob_response = bob.respond_to_handshake(alice_handshake)
        print("Handshake response size:", len(bob_response), "bytes")
        print("Bob created session with ID:", list(bob.sessions.keys())[0].hex()[:8] + "...")
    except Exception as e:
        print("Error:", e)
        return None, None, None
    print()
    
    print("4. Alice finalizes handshake...")
    try:
        session_id = alice.finalize_handshake(bob_response)
        print("Alice created session with ID:", session_id.hex()[:8] + "...")
        print("Session successfully established!")
    except Exception as e:
        print("Error:", e)
        return None, None, None
    print()
    
    print("5. Verifying shared keys...")
    alice_session = alice.sessions[session_id]
    bob_session = bob.sessions[list(bob.sessions.keys())[0]]
    
    print("Root keys match:", alice_session['root_key'] == bob_session['root_key'])
    print()
    
    return alice, bob, session_id

def demo_messaging():
    """
    Demonstrates message exchange with Double Ratchet.
    """
    alice, bob, session_id = demo_handshake()
    if not alice or not bob or not session_id:
        return
        
    print("=== Message Exchange Demonstration ===\n")
    
    # Alice sends the first message
    print("6. Alice sends the first message to Bob...")
    message1 = b"Hello from Alice!"
    aad1 = b"message_1_aad"
    try:
        ciphertext1 = alice.encrypt_message(session_id, message1, aad1)
    except RuntimeError as e:
        print(f"❌ Encryption error: {e}")
        return

    # Bob decrypts the message
    try:
        plaintext1 = bob.decrypt_message(ciphertext1, aad1)
        print(f"Bob received a message from Alice: '{plaintext1.decode()}'")
        assert plaintext1 == message1
    except Exception as e:
        print(f"❌ Error decrypting the first message: {e}")
        return
    print("Chain keys updated.")
    print()
    
    # Bob sends a reply
    print("7. Bob sends a reply to Alice...")
    message2 = b"Hello to Alice! From Bob."
    aad2 = b"message_2_aad"
    try:
        ciphertext2 = bob.encrypt_message(list(bob.sessions.keys())[0], message2, aad2)
    except RuntimeError as e:
        print(f"❌ Encryption error: {e}")
        return
    
    # Alice decrypts the reply
    try:
        plaintext2 = alice.decrypt_message(ciphertext2, aad2)
        print(f"   Alice received a message from Bob: '{plaintext2.decode()}'")
        assert plaintext2 == message2
    except Exception as e:
        print(f"Error decrypting the second message: {e}")
        return
    print("Chain keys updated again.")
    print()

    # Check session states
    print("8. Checking final session states:")
    alice_session = alice.sessions[session_id]
    bob_session = bob.sessions[list(bob.sessions.keys())[0]]
    print("Alice -> Sent messages:", alice_session['message_numbers']['send'])
    print("Bob   -> Received messages:", bob_session['message_numbers']['recv'])
    print("Bob   -> Sent messages:", bob_session['message_numbers']['send'])
    print("Alice -> Received messages:", alice_session['message_numbers']['recv'])
    
    print("\n✅ Demonstration completed successfully. The protocol works correctly.")

if __name__ == "__main__":
    check_kyber_support()
    demo_messaging()