"""
server.py
Password manager server.

The server is intentionally "dumb": it stores public keys, encrypted vault
blobs, and signatures, but it can never read a master password, a DEK/KEK,
or any plaintext vault entry.

Handshake (per connection, gives forward secrecy):
  1. Server generates a fresh ephemeral X25519 keypair for this connection,
     and sends: its long-term RSA public key (identity / CA key), the
     ephemeral X25519 public key, and an RSA signature over that ephemeral
     key. This signature is what stops a man-in-the-middle from swapping in
     their own ephemeral key.
  2. Client verifies the signature, generates its own ephemeral X25519
     keypair, and sends its ephemeral public key back.
  3. Both sides run X25519 Diffie-Hellman and feed the shared secret through
     HKDF-SHA256 to get an AES-256 session key. The session key itself is
     never transmitted - even if this exact conversation were recorded and
     the server's long-term RSA key leaked later, past sessions can't be
     decrypted (forward secrecy), unlike plain RSA key transport.
  4. All further messages in this connection are AES-GCM encrypted under
     that session key.

Encrypted message "type"s handled:
  register          - new user: stores username, RSA public key, PBKDF2 salt;
                       server (acting as a mini-CA) issues and returns a
                       certificate binding the username to that public key
  get_certificate    - fetch any user's certificate, to verify a public key
                       actually belongs to that username before trusting it
  login_challenge    - step 1 of challenge/response auth: server sends a nonce
  login_verify       - step 2: client proves possession of the private key by
                       signing the nonce; server verifies with stored public key
  upload_vault       - stores an AES-GCM encrypted vault blob + RSA signature
  download_vault     - returns the stored blob + signature
"""

import os
import json
import socket
import secrets
import threading

import crypto_utils as cu
import network as net

HOST = "127.0.0.1"
PORT = 5050
DB_FILE = os.path.join(os.path.dirname(__file__), "server_db.json")

db_lock = threading.Lock()
pending_challenges = {}  # username -> nonce bytes (per-process; fine for a demo)


def load_db() -> dict:
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}


def save_db(db: dict):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def handle_client(conn: socket.socket, addr, ca_private_key, ca_public_pem: bytes):
    print(f"[+] Connection from {addr}")
    try:
        # Step 1: ephemeral ECDH keypair for this connection only
        ec_private, ec_public = cu.generate_ec_keypair()
        ec_public_raw = cu.serialize_ec_public_key(ec_public)
        ec_sig = cu.rsa_sign(ca_private_key, ec_public_raw)  # authenticates the ephemeral key

        net.send_msg(conn, {
            "type": "hello",
            "rsa_pub": ca_public_pem.decode(),
            "ecdh_pub": cu.b64(ec_public_raw),
            "ecdh_sig": cu.b64(ec_sig),
        })

        # Step 2: receive the client's ephemeral public key (sent in the clear,
        # it's only a Diffie-Hellman public value, not a secret)
        msg = net.recv_msg(conn)
        if msg.get("type") != "client_ecdh":
            net.send_msg(conn, {"type": "error", "message": "expected client_ecdh"})
            return
        client_ec_public = cu.load_ec_public_key(cu.unb64(msg["ecdh_pub"]))

        # Step 3: derive the shared AES session key (never sent over the wire)
        shared_secret = cu.ec_shared_secret(ec_private, client_ec_public)
        session_key = cu.hkdf_derive(shared_secret)
        print(f"    forward-secret session key established with {addr}")

        # Step 4: handle encrypted application messages
        while True:
            outer = net.recv_msg(conn)
            if outer.get("type") != "secure":
                net.send_msg(conn, {"type": "error", "message": "expected secure message"})
                continue

            try:
                plaintext = cu.aes_decrypt(session_key, cu.unb64(outer["enc"]))
            except Exception:
                net.send_msg(conn, {"type": "error", "message": "decryption failed"})
                continue

            inner = json.loads(plaintext.decode("utf-8"))
            response = process_message(inner, ca_private_key)

            enc = cu.aes_encrypt(session_key, json.dumps(response).encode())
            net.send_msg(conn, {"type": "secure", "enc": cu.b64(enc)})

            if response.get("type") == "bye":
                break

    except ConnectionError:
        pass
    finally:
        conn.close()
        print(f"[-] Disconnected {addr}")


def process_message(inner: dict, ca_private_key) -> dict:
    msg_type = inner.get("type")

    with db_lock:
        db = load_db()

        if msg_type == "register":
            username = inner["username"]
            if username in db:
                return {"type": "error", "message": "username already exists"}

            public_key_pem = inner["public_key"]
            # Server acts as a mini-CA: issue a certificate binding this
            # username to this public key, signed with the server's own
            # private key. Anyone who trusts the server's public key can
            # later verify this binding, instead of just trusting whatever
            # public key happens to be sitting in the database.
            cert_sig = cu.issue_certificate(ca_private_key, username, public_key_pem)

            db[username] = {
                "public_key": public_key_pem,
                "salt": inner["salt"],
                "cert_signature": cu.b64(cert_sig),
                "vault_blob": None,
                "vault_sig": None,
            }
            save_db(db)
            return {
                "type": "register_ok",
                "certificate": {
                    "username": username,
                    "public_key": public_key_pem,
                    "signature": cu.b64(cert_sig),
                },
            }

        if msg_type == "get_certificate":
            username = inner["username"]
            user = db.get(username)
            if not user:
                return {"type": "error", "message": "no such user"}
            return {
                "type": "certificate",
                "username": username,
                "public_key": user["public_key"],
                "signature": user["cert_signature"],
            }

        if msg_type == "get_salt":
            username = inner["username"]
            user = db.get(username)
            if not user:
                return {"type": "error", "message": "no such user"}
            return {"type": "salt", "salt": user["salt"]}

        if msg_type == "login_challenge":
            username = inner["username"]
            if username not in db:
                return {"type": "error", "message": "no such user"}
            nonce = secrets.token_bytes(32)
            pending_challenges[username] = nonce
            return {"type": "challenge", "nonce": cu.b64(nonce)}

        if msg_type == "login_verify":
            username = inner["username"]
            user = db.get(username)
            nonce = pending_challenges.pop(username, None)
            if not user or nonce is None:
                return {"type": "error", "message": "no pending challenge"}
            public_key = cu.load_public_key(user["public_key"].encode())
            signature = cu.unb64(inner["signature"])
            if cu.rsa_verify(public_key, nonce, signature):
                return {"type": "login_ok"}
            return {"type": "error", "message": "signature verification failed"}

        if msg_type == "upload_vault":
            username = inner["username"]
            user = db.get(username)
            if not user:
                return {"type": "error", "message": "no such user"}
            public_key = cu.load_public_key(user["public_key"].encode())
            blob = cu.unb64(inner["blob"])
            signature = cu.unb64(inner["signature"])
            # Verify the client's signature over the ciphertext before storing it
            # -> this is the non-repudiation check: only this user's private key
            #    could have produced a valid signature over this exact blob.
            if not cu.rsa_verify(public_key, blob, signature):
                return {"type": "error", "message": "vault signature invalid"}
            user["vault_blob"] = inner["blob"]
            user["vault_sig"] = inner["signature"]
            save_db(db)
            return {"type": "upload_ok"}

        if msg_type == "download_vault":
            username = inner["username"]
            user = db.get(username)
            if not user or user["vault_blob"] is None:
                return {"type": "error", "message": "no vault stored"}
            return {
                "type": "vault_data",
                "blob": user["vault_blob"],
                "signature": user["vault_sig"],
            }

        if msg_type == "bye":
            return {"type": "bye"}

    return {"type": "error", "message": f"unknown message type {msg_type}"}


def main():
    # Server's own long-term RSA identity, doubling as the CA key that signs
    # username<->public-key certificates. Generated once per server run; in a
    # real deployment this would be loaded from disk/HSM so it survives restarts.
    ca_private_key, ca_public_key = cu.generate_rsa_keypair()
    ca_public_pem = cu.serialize_public_key(ca_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Password manager server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, ca_private_key, ca_public_pem),
                daemon=True,
            )
            t.start()


if __name__ == "__main__":
    main()