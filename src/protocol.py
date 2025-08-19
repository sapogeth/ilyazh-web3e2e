# src/protocol.py
import struct
import os
import time
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
import pyoqs as oqs
import cbor2
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IlyazhProtocol:
    """
    Class implementing the Ilyazh-Web3E2E protocol.
    """
    VERSION = 0x03
    SUITE_ID = 0x0001
    MAX_MESSAGES_PER_CHAIN = 2**20
    MAX_MESSAGES_PER_SESSION = 2**32
    MAX_SESSION_AGE_SECONDS = 24 * 60 * 60 # 24 hours

    def __init__(self, identity_private=None):
        # Long-term keys
        if identity_private:
            self.identity_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(identity_private)
        else:
            self.identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self.identity_public_key = self.identity_private_key.public_key()
        
        # Session states
        self.sessions = {}  
        self.handshake_cache = {}  
    
    def get_identity_public_bytes(self):
        """Get the public key in bytes"""
        return self.identity_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def _hkdf_expand(self, key, info, length):
        """Helper function for HKDF-Expand"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(key)

    # ---------------- Handshake ----------------
    def initiate_handshake(self, peer_identity_public):
        """Initiates a handshake with another participant"""
        session_id = os.urandom(16)
        
        # Generate ephemeral X25519
        ephemeral_x25519_private = x25519.X25519PrivateKey.generate()
        ephemeral_x25519_public = ephemeral_x25519_private.public_key()
        
        # Generate ephemeral Kyber768
        kem = oqs.KeyEncapsulation("Kyber768")
        ephemeral_kyber_public = kem.generate_keypair()
        ephemeral_kyber_private = kem.export_secret_key()
        
        # Sign ephemeral keys
        combined_public = (
            ephemeral_x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) + ephemeral_kyber_public
        )
        signature = self.identity_private_key.sign(combined_public)
        
        # Save handshake state
        self.handshake_cache[session_id] = {
            'x25519_private': ephemeral_x25519_private,
            'kyber_private': ephemeral_kyber_private,
            'peer_identity_public': peer_identity_public,
            'timestamp': time.time()
        }
        
        handshake_msg = {
            'version': self.VERSION,
            'suite_id': self.SUITE_ID,
            'session_id': session_id,
            'identity_public': self.get_identity_public_bytes(),
            'x25519_public': ephemeral_x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            'kyber_public': ephemeral_kyber_public,
            'signature': signature
        }
        
        return cbor2.dumps(handshake_msg)
    
    def respond_to_handshake(self, handshake_data):
        """Process an incoming handshake"""
        try:
            handshake_msg = cbor2.loads(handshake_data)
        except:
            raise ValueError("Invalid handshake format")
        
        if handshake_msg.get('version') != self.VERSION or handshake_msg.get('suite_id') != self.SUITE_ID:
            raise ValueError("Unsupported protocol version or crypto suite")
        
        # Verify the signature
        peer_identity_public_key = ed25519.Ed25519PublicKey.from_public_bytes(handshake_msg['identity_public'])
        combined_public = handshake_msg['x25519_public'] + handshake_msg['kyber_public']
        peer_identity_public_key.verify(handshake_msg['signature'], combined_public)
        
        # Generate our ephemeral keys
        ephemeral_x25519_private = x25519.X25519PrivateKey.generate()
        ephemeral_x25519_public = ephemeral_x25519_private.public_key()
        
        kem = oqs.KeyEncapsulation("Kyber768")
        ephemeral_kyber_public = kem.generate_keypair()
        ephemeral_kyber_private = kem.export_secret_key()
        
        # Encapsulate the key for the peer
        kem_ciphertext, kem_shared_secret = kem.encap_secret(handshake_msg['kyber_public'])
        
        # DH X25519
        x25519_shared_secret = ephemeral_x25519_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(handshake_msg['x25519_public'])
        )
        
        combined_secret = x25519_shared_secret + kem_shared_secret
        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ilyazh-root-key',
            backend=default_backend()
        ).derive(combined_secret)
        
        session_id = handshake_msg['session_id']
        self.sessions[session_id] = {
            'root_key': root_key,
            'sending_chain': None,
            'receiving_chain': None,
            'peer_identity_public': handshake_msg['identity_public'],
            'nonce_prefix': os.urandom(8),
            'message_numbers': {'send': 0, 'recv': 0},
            'sending_ratchet_private': None,
            'sending_ratchet_public': None,
            'receiving_ratchet_public': handshake_msg['x25519_public'],
            'last_activity': time.time(),
            'session_start_time': time.time(),
            'nonces_used': set() # Added for nonce verification
        }
        
        combined_public_resp = (
            ephemeral_x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) + ephemeral_kyber_public
        )
        signature_resp = self.identity_private_key.sign(combined_public_resp)
        
        response_msg = {
            'version': self.VERSION,
            'suite_id': self.SUITE_ID,
            'session_id': session_id,
            'identity_public': self.get_identity_public_bytes(),
            'x25519_public': ephemeral_x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            'kyber_public': ephemeral_kyber_public,
            'kem_ciphertext': kem_ciphertext,
            'signature': signature_resp
        }
        
        self.handshake_cache[session_id] = {
            'x25519_private': ephemeral_x25519_private,
            'kyber_private': ephemeral_kyber_private,
            'peer_identity_public': handshake_msg['identity_public'],
            'timestamp': time.time()
        }
        
        return cbor2.dumps(response_msg)
    
    def finalize_handshake(self, handshake_response):
        """Finalizes the handshake after receiving the response"""
        response_msg = cbor2.loads(handshake_response)
        session_id = response_msg['session_id']
        
        # Verify the signature
        peer_identity_public_key = ed25519.Ed25519PublicKey.from_public_bytes(response_msg['identity_public'])
        combined_public = response_msg['x25519_public'] + response_msg['kyber_public']
        peer_identity_public_key.verify(response_msg['signature'], combined_public)
        
        # Decapsulate Kyber
        kem = oqs.KeyEncapsulation("Kyber768")
        kem.import_secret_key(self.handshake_cache[session_id]['kyber_private'])
        kem_shared_secret = kem.decap_secret(response_msg['kem_ciphertext'])
        
        # DH X25519
        x25519_shared_secret = self.handshake_cache[session_id]['x25519_private'].exchange(
            x25519.X25519PublicKey.from_public_bytes(response_msg['x25519_public'])
        )
        
        combined_secret = x25519_shared_secret + kem_shared_secret
        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ilyazh-root-key',
            backend=default_backend()
        ).derive(combined_secret)
        
        self.sessions[session_id] = {
            'root_key': root_key,
            'sending_chain': None,
            'receiving_chain': None,
            'peer_identity_public': response_msg['identity_public'],
            'nonce_prefix': os.urandom(8),
            'message_numbers': {'send': 0, 'recv': 0},
            'sending_ratchet_private': self.handshake_cache[session_id]['x25519_private'],
            'sending_ratchet_public': self.handshake_cache[session_id]['x25519_private'].public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            'receiving_ratchet_public': response_msg['x25519_public'],
            'last_activity': time.time(),
            'session_start_time': time.time(),
            'nonces_used': set()
        }
        
        del self.handshake_cache[session_id]
        return session_id

    # ---------------- Double Ratchet ----------------
    def _kdf_rk(self, root_key, input_key_material):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=root_key,
            info=b'ilyazh-kdf-rk',
            backend=default_backend()
        )
        output = hkdf.derive(input_key_material)
        return output[:32], output[32:]
    
    def _kdf_ck(self, chain_key):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=chain_key,
            info=b'ilyazh-kdf-ck',
            backend=default_backend()
        )
        output = hkdf.derive(b'')
        return output[:32], output[32:]

    def _update_sending_chain(self, session):
        if session['sending_chain'] is None:
            session['sending_chain'] = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=session['root_key'],
                info=b'ilyazh-initial-chain',
                backend=default_backend()
            ).derive(b'initial-chain')
        
        message_key, new_chain_key = self._kdf_ck(session['sending_chain'])
        session['sending_chain'] = new_chain_key
        session['message_numbers']['send'] += 1
        return message_key

    def _update_receiving_chain(self, session, dh_output):
        session['root_key'], session['receiving_chain'] = self._kdf_rk(session['root_key'], dh_output)
        session['message_numbers']['recv'] = 0
        session['nonce_prefix'] = os.urandom(8)
    
    # ---------------- Messaging ----------------
    def encrypt_message(self, session_id, message, associated_data=b''):
        if session_id not in self.sessions:
            raise ValueError("Unknown session ID")
        session = self.sessions[session_id]

        # Check session limits
        if session['message_numbers']['send'] >= self.MAX_MESSAGES_PER_SESSION or \
           time.time() - session['session_start_time'] >= self.MAX_SESSION_AGE_SECONDS:
            raise RuntimeError("Session has expired. MUST re-establish.")
        
        # Check for need for DH Ratchet
        ratchet_public = None
        if session['message_numbers']['send'] == 0:
            # DH Ratchet occurs on the first message
            new_ratchet_private = x25519.X25519PrivateKey.generate()
            session['sending_ratchet_private'] = new_ratchet_private
            ratchet_public = new_ratchet_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            session['sending_ratchet_public'] = ratchet_public
            
            dh_output = new_ratchet_private.exchange(
                x25519.X25519PublicKey.from_public_bytes(session['receiving_ratchet_public'])
            )
            
            session['root_key'], session['sending_chain'] = self._kdf_rk(session['root_key'], dh_output)
        else:
            ratchet_public = session['sending_ratchet_public']
        
        message_key = self._update_sending_chain(session)
        counter = session['message_numbers']['send'].to_bytes(4, 'big')
        nonce = session['nonce_prefix'] + counter
        
        # AAD should include the header for authentication
        header = cbor2.dumps({
            'version': self.VERSION,
            'suite_id': self.SUITE_ID,
            'session_id': session_id,
            'sequence_num': session['message_numbers']['send'],
            'ratchet_public': ratchet_public,
            'nonce_prefix': session['nonce_prefix'] # Added for recipient-side nonce verification
        })
        aad = header + associated_data
        
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(message) + encryptor.finalize()
        session['last_activity'] = time.time()
        
        return cbor2.dumps({
            'header': header,
            'ciphertext': ciphertext,
            'auth_tag': encryptor.tag
        })
    
    def decrypt_message(self, message, associated_data=b''):
        full_payload = cbor2.loads(message)
        header = full_payload['header']
        ciphertext = full_payload['ciphertext']
        auth_tag = full_payload['auth_tag']
        
        message_data = cbor2.loads(header)
        session_id = message_data['session_id']
        session = self.sessions[session_id]

        new_ratchet_public = message_data.get('ratchet_public')
        if new_ratchet_public and new_ratchet_public != session['receiving_ratchet_public']:
            if session['sending_ratchet_private'] is None:
                raise ValueError("Cannot perform DH ratchet, no sending key.")
            
            dh_output = session['sending_ratchet_private'].exchange(
                x25519.X25519PublicKey.from_public_bytes(new_ratchet_public)
            )
            self._update_receiving_chain(session, dh_output)
            session['receiving_ratchet_public'] = new_ratchet_public
            session['nonces_used'].clear() # Clear the list of used nonces on DH Ratchet

        if session['receiving_chain'] is None:
            session['receiving_chain'] = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=session['root_key'],
                info=b'ilyazh-initial-chain',
                backend=default_backend()
            ).derive(b'initial-chain')
        
        message_key, new_chain_key = self._kdf_ck(session['receiving_chain'])
        session['receiving_chain'] = new_chain_key
        
        counter = message_data['sequence_num'].to_bytes(4, 'big')
        nonce = session['nonce_prefix'] + counter

        # Check for nonce reuse
        if nonce in session['nonces_used']:
            raise ValueError("Nonce reuse detected, a critical security failure.")
        session['nonces_used'].add(nonce)

        aad = header + associated_data
        
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.GCM(nonce, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        session['message_numbers']['recv'] += 1
        session['last_activity'] = time.time()
        
        return plaintext
    
    def cleanup_sessions(self, max_age=3600):
        current_time = time.time()
        expired_sessions = [sid for sid, s in self.sessions.items() if current_time - s['last_activity'] > max_age]
        for sid in expired_sessions:
            del self.sessions[sid]
        expired_handshakes = [sid for sid, h in self.handshake_cache.items() if current_time - h['timestamp'] > max_age]
        for sid in expired_handshakes:
            del self.handshake_cache[sid]