import sys
import time
sys.path.append('src')

from protocol import IlyazhProtocol
from demo_messaging import demo_handshake

def stress_test():
    print("=== Protocol Stress Test ===\n")
    
    # Establish a session
    alice, bob, session_id = demo_handshake()
    if not alice or not bob or not session_id:
        return
        
    # Send many messages
    print("6. Sending 1000 messages...")
    start_time = time.time()
    
    for i in range(1000):
        message = f"Message {i}: The quick brown fox jumps over the lazy dog".encode()
        aad = f"message_num:{i};test:stress".encode()
        
        try:
            # Alice sends a message to Bob
            ciphertext = alice.encrypt_message(session_id, message, aad)
            plaintext = bob.decrypt_message(ciphertext, aad)
            
            if plaintext != message:
                print(f"❌ Error in message {i}: mismatch!")
                return
                
            if i % 100 == 0:
                print(f"Processed {i} messages")
                
        except Exception as e:
            print(f"❌ Error in message {i}: {e}")
            return
    
    end_time = time.time()
    print()
    
    # Show results
    print("7. Stress test results:")
    print("Total messages:", 1000)
    print("Total time:", round(end_time - start_time, 2), "seconds")
    print("Messages per second:", round(1000 / (end_time - start_time), 2))
    print("Alice session state:")
    print("Sent:", alice.sessions[session_id]['message_numbers']['send'])
    print("Received:", alice.sessions[session_id]['message_numbers']['recv'])
    
    bob_session_id = list(bob.sessions.keys())[0]
    print("Bob session state:")
    print("Sent:", bob.sessions[bob_session_id]['message_numbers']['send'])
    print("Received:", bob.sessions[bob_session_id]['message_numbers']['recv'])
    
    print("\n✅ Stress test completed successfully.")

if __name__ == "__main__":
    stress_test