# sdemo_handshake.py
"""
Demonstration of a full handshake between two participants
"""

import os
import sys
sys.path.append('src')

from protocol import IlyazhProtocol
import cbor2

def demo_handshake():
    print("=== Ilyazh-Web3E2E Handshake Demonstration ===\n")
    
    # Create two participants
    print("1. Creating participants...")
    alice = IlyazhProtocol()
    bob = IlyazhProtocol()
    
    print("Alice identity: ", alice.get_identity_public_bytes().hex()[:16] + "...")
    print("Bob identity:   ", bob.get_identity_public_bytes().hex()[:16] + "...")
    print()
    
    # Alice initiates the handshake
    print("2. Alice initiates handshake...")
    alice_handshake = alice.initiate_handshake(bob.get_identity_public_bytes())
    print("Handshake message size:", len(alice_handshake), "bytes")
    print()
    
    # Bob processes the handshake
    print("3. Bob processes handshake...")
    try:
        bob_response = bob.respond_to_handshake(alice_handshake)
        print("Handshake response size:", len(bob_response), "bytes")
        print("Bob created session with ID:", list(bob.sessions.keys())[0].hex()[:8] + "...")
    except Exception as e:
        print("Error:", e)
        return
    print()
    
    # Alice finalizes the 
    print("4. Alice finalizes handshake...")
    try:
        session_id = alice.finalize_handshake(bob_response)
        print("Alice created session with ID:", session_id.hex()[:8] + "...")
        print("Session successfully established!")
    except Exception as e:
        print("Error:", e)
        return
    print()
    
    # Check that the keys match
    print("5. Verifying shared keys...")
    alice_session = alice.sessions[session_id]
    bob_session = bob.sessions[list(bob.sessions.keys())[0]]
    
    print("Root keys match:", alice_session['root_key'] == bob_session['root_key'])
    print("Alice sending chain:", alice_session.get('sending_chain') is not None)
    print("Bob receiving chain:", bob_session.get('receiving_chain') is not None)
    print()
    
    return alice, bob, session_id

if __name__ == "__main__":
    alice, bob, session_id = demo_handshake()