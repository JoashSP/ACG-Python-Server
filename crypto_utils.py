"""
crypto_utils.py
Shared cryptographic helper functions for the password manager.

Layers used:
- Hashing/KDF   : derive a key from the user's master password (PBKDF2-HMAC-SHA256),
                  and HKDF-SHA256 to turn a raw Diffie-Hellman shared secret into
                  a usable AES key
- AES-256-GCM   : symmetric encryption. Two separate uses:
                    1) wraps the vault's Data Encryption Key (DEK) under the
                       password-derived Key Encryption Key (KEK)
                    2) encrypts the vault contents under the DEK, and encrypts
                       all network traffic under the session key
- X25519 (ECDH) : ephemeral Diffie-Hellman key agreement, used to establish the
                  AES session key for each connection without ever transmitting
                  it (forward secrecy)
- RSA-2048      : digital signatures only. Used to (a) authenticate the
                  server's ephemeral ECDH key during the handshake, (b) prove
                  possession of a private key during login, (c) sign vault
                  uploads for non-repudiation, and (d) as the server's CA
                  ("certificate authority") key that signs username<->public-key
                  certificates at registration
"""

import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Key derivation (master password -> AES key)
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    return os.urandom(16)


def derive_key_from_password(password: str, salt: bytes, iterations: int = 390_000) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def hkdf_derive(shared_secret: bytes, info: bytes = b"session key", length: int = 32) -> bytes:
    """Turn a raw ECDH shared secret into a uniformly-random AES key."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# AES-256-GCM (confidentiality + integrity)
# ---------------------------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    """Returns nonce(12) || ciphertext(includes 16-byte auth tag)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def aes_decrypt(key: bytes, data: bytes, associated_data: bytes = None) -> bytes:
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)


# ---------------------------------------------------------------------------
# RSA (key transport + digital signatures)
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def serialize_private_key(private_key, password: bytes = None) -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def load_private_key(pem_bytes: bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """Used to wrap a fresh AES session key under the recipient's RSA public key."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_sign(private_key, data: bytes) -> bytes:
    """Sign data with RSA-PSS/SHA-256 -> provides non-repudiation."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# X25519 (ECDH) - ephemeral key agreement for forward-secret session keys
# ---------------------------------------------------------------------------

def generate_ec_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def serialize_ec_public_key(public_key) -> bytes:
    """Raw 32-byte encoding - compact enough to sign and send directly."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_ec_public_key(raw_bytes: bytes):
    return x25519.X25519PublicKey.from_public_bytes(raw_bytes)


def ec_shared_secret(private_key, peer_public_key) -> bytes:
    """Diffie-Hellman exchange. The result is raw key material, not yet a key
    - always run it through hkdf_derive() before using it as an AES key."""
    return private_key.exchange(peer_public_key)


# ---------------------------------------------------------------------------
# CA certificates: binds a username to a public key, signed by the server's
# long-term RSA key acting as a mini Certificate Authority. Prevents a
# compromised/lied-to database from silently swapping a user's public key
# without detection, since the swapped key would no longer match the
# original CA signature.
# ---------------------------------------------------------------------------

def certificate_bytes(username: str, public_key_pem: str) -> bytes:
    return f"{username}|{public_key_pem}".encode("utf-8")


def issue_certificate(ca_private_key, username: str, public_key_pem: str) -> bytes:
    return rsa_sign(ca_private_key, certificate_bytes(username, public_key_pem))


def verify_certificate(ca_public_key, username: str, public_key_pem: str, signature: bytes) -> bool:
    return rsa_verify(ca_public_key, certificate_bytes(username, public_key_pem), signature)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))