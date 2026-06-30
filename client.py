"""
client.py
Password manager client (CLI).

Local files for each user, under client_data/<username>/:
  private_key.pem  - RSA private key, PEM-encrypted under the master password
  public_key.pem   - RSA public key (also registered with the server)
  salt.bin         - PBKDF2 salt used to derive the KEK from the master password
  wrapped_dek.bin  - the random Data Encryption Key (DEK), AES-GCM encrypted
                     under the KEK
  vault.enc        - AES-256-GCM encrypted vault (local cache), encrypted
                     under the DEK - same blob that gets signed and uploaded
  certificate.json - the CA-signed certificate binding this username to this
                     public key, received at registration

Local file shared across all users on this device, under client_data/:
  ca_public_key.pem - the server's RSA public key, pinned the first time we
                      ever connect (trust-on-first-use). Every later
                      connection's handshake is checked against this pinned
                      copy, so a server impersonator can't just hand us a
                      different key.

Key hierarchy:
  master password --[PBKDF2-HMAC-SHA256]--> KEK
  KEK --[AES-256-GCM, "wraps"]--> DEK (random, generated once at registration)
  DEK --[AES-256-GCM]--> vault contents

  Wrapping the DEK separately from encrypting the vault means changing your
  master password only needs to re-wrap a 32-byte DEK, not re-encrypt the
  whole vault - see change_master_password().

Nothing here is ever stored or sent in plaintext: the master password itself
is discarded right after deriving the KEK; the RSA private key is encrypted
under the master password; every vault upload is signed for non-repudiation;
and the connection to the server uses an ephemeral ECDH handshake (forward
secrecy) authenticated by the server's RSA signature.
"""

import os
import json
import socket
import getpass

import crypto_utils as cu
import network as net

HOST = "127.0.0.1"
PORT = 5050
DATA_DIR = os.path.join(os.path.dirname(__file__), "client_data")
CA_KEY_PATH = os.path.join(DATA_DIR, "ca_public_key.pem")


# ---------------------------------------------------------------------------
# Local storage helpers
# ---------------------------------------------------------------------------

def user_dir(username: str) -> str:
    path = os.path.join(DATA_DIR, username)
    os.makedirs(path, exist_ok=True)
    return path


def save_local_identity(username, private_pem, public_pem, salt, wrapped_dek):
    d = user_dir(username)
    with open(os.path.join(d, "private_key.pem"), "wb") as f:
        f.write(private_pem)
    with open(os.path.join(d, "public_key.pem"), "wb") as f:
        f.write(public_pem)
    with open(os.path.join(d, "salt.bin"), "wb") as f:
        f.write(salt)
    with open(os.path.join(d, "wrapped_dek.bin"), "wb") as f:
        f.write(wrapped_dek)


def load_local_identity(username, password):
    d = user_dir(username)
    with open(os.path.join(d, "private_key.pem"), "rb") as f:
        private_key = cu.load_private_key(f.read(), password=password.encode())
    with open(os.path.join(d, "public_key.pem"), "rb") as f:
        public_key = cu.load_public_key(f.read())
    with open(os.path.join(d, "salt.bin"), "rb") as f:
        salt = f.read()
    with open(os.path.join(d, "wrapped_dek.bin"), "rb") as f:
        wrapped_dek = f.read()
    return private_key, public_key, salt, wrapped_dek


def save_certificate(username, certificate: dict):
    with open(os.path.join(user_dir(username), "certificate.json"), "w") as f:
        json.dump(certificate, f, indent=2)


def load_certificate(username):
    path = os.path.join(user_dir(username), "certificate.json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def save_local_vault_blob(username, blob: bytes):
    with open(os.path.join(user_dir(username), "vault.enc"), "wb") as f:
        f.write(blob)


def load_local_vault_blob(username):
    path = os.path.join(user_dir(username), "vault.enc")
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def load_or_pin_ca_key(received_pem: str):
    """Trust-on-first-use: the first time we ever talk to a server, remember
    its public key. Every later handshake is checked against this pinned
    copy - if a different key ever shows up, that's a sign of server
    impersonation or a man-in-the-middle, so we refuse to continue."""
    if os.path.exists(CA_KEY_PATH):
        with open(CA_KEY_PATH, "r") as f:
            pinned_pem = f.read()
        if pinned_pem.strip() != received_pem.strip():
            raise RuntimeError(
                "Server's public key does not match the one pinned on first "
                "connection. Refusing to continue - this could be a "
                "man-in-the-middle or an impersonating server."
            )
        return cu.load_public_key(pinned_pem.encode())
    else:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CA_KEY_PATH, "w") as f:
            f.write(received_pem)
        print("(first connection - pinned the server's public key for future checks)")
        return cu.load_public_key(received_pem.encode())


# ---------------------------------------------------------------------------
# Network handshake (ECDH, authenticated by RSA signature) + secure messaging
# ---------------------------------------------------------------------------

def connect_and_handshake():
    sock = socket.create_connection((HOST, PORT))
    hello = net.recv_msg(sock)

    ca_public_key = load_or_pin_ca_key(hello["rsa_pub"])

    server_ec_public_raw = cu.unb64(hello["ecdh_pub"])
    ec_sig = cu.unb64(hello["ecdh_sig"])
    if not cu.rsa_verify(ca_public_key, server_ec_public_raw, ec_sig):
        sock.close()
        raise RuntimeError("Server's ephemeral key signature did not verify - aborting handshake.")

    server_ec_public = cu.load_ec_public_key(server_ec_public_raw)
    client_ec_private, client_ec_public = cu.generate_ec_keypair()
    net.send_msg(sock, {
        "type": "client_ecdh",
        "ecdh_pub": cu.b64(cu.serialize_ec_public_key(client_ec_public)),
    })

    shared_secret = cu.ec_shared_secret(client_ec_private, server_ec_public)
    session_key = cu.hkdf_derive(shared_secret)  # never sent over the wire
    return sock, session_key


def secure_send(sock, session_key, inner: dict):
    enc = cu.aes_encrypt(session_key, json.dumps(inner).encode())
    net.send_msg(sock, {"type": "secure", "enc": cu.b64(enc)})


def secure_recv(sock, session_key) -> dict:
    outer = net.recv_msg(sock)
    plaintext = cu.aes_decrypt(session_key, cu.unb64(outer["enc"]))
    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# Vault (de)serialization
# ---------------------------------------------------------------------------

def encrypt_vault(dek: bytes, entries: list) -> bytes:
    return cu.aes_encrypt(dek, json.dumps(entries).encode())


def decrypt_vault(dek: bytes, blob: bytes) -> list:
    return json.loads(cu.aes_decrypt(dek, blob).decode())


# ---------------------------------------------------------------------------
# High-level actions
# ---------------------------------------------------------------------------

def register():
    username = input("Choose a username: ").strip()
    password = getpass.getpass("Choose a master password: ")

    private_key, public_key = cu.generate_rsa_keypair()
    private_pem = cu.serialize_private_key(private_key, password=password.encode())
    public_pem = cu.serialize_public_key(public_key)
    salt = cu.generate_salt()

    # Key hierarchy: KEK derived from password, DEK random and wrapped by the KEK
    kek = cu.derive_key_from_password(password, salt)
    dek = os.urandom(32)
    wrapped_dek = cu.aes_encrypt(kek, dek)

    save_local_identity(username, private_pem, public_pem, salt, wrapped_dek)
    save_local_vault_blob(username, encrypt_vault(dek, []))

    sock, session_key = connect_and_handshake()
    secure_send(sock, session_key, {
        "type": "register",
        "username": username,
        "public_key": public_pem.decode(),
        "salt": cu.b64(salt),
    })
    reply = secure_recv(sock, session_key)
    secure_send(sock, session_key, {"type": "bye"})
    secure_recv(sock, session_key)
    sock.close()

    if reply.get("type") == "register_ok":
        save_certificate(username, reply["certificate"])
        print(f"Registered '{username}'.")
        print("Private key stored locally, encrypted under your master password.")
        print("Server issued and signed a certificate binding your username to your public key.")
    else:
        print(f"Registration failed: {reply.get('message')}")


def login():
    username = input("Username: ").strip()
    password = getpass.getpass("Master password: ")

    try:
        private_key, public_key, salt, wrapped_dek = load_local_identity(username, password)
    except Exception:
        print("Could not unlock local identity (wrong password, or no local account on this device).")
        return None

    kek = cu.derive_key_from_password(password, salt)
    try:
        dek = cu.aes_decrypt(kek, wrapped_dek)
    except Exception:
        print("Could not unwrap the vault key - wrong master password.")
        return None

    sock, session_key = connect_and_handshake()

    secure_send(sock, session_key, {"type": "login_challenge", "username": username})
    reply = secure_recv(sock, session_key)
    if reply.get("type") != "challenge":
        print(f"Login failed: {reply.get('message')}")
        sock.close()
        return None

    nonce = cu.unb64(reply["nonce"])
    signature = cu.rsa_sign(private_key, nonce)  # proves possession of the private key
    secure_send(sock, session_key, {
        "type": "login_verify",
        "username": username,
        "signature": cu.b64(signature),
    })
    reply = secure_recv(sock, session_key)
    if reply.get("type") != "login_ok":
        print(f"Login failed: {reply.get('message')}")
        sock.close()
        return None

    print(f"Logged in as '{username}'.")
    return {
        "username": username,
        "private_key": private_key,
        "public_key": public_key,
        "kek": kek,
        "dek": dek,
        "salt": salt,
        "sock": sock,
        "session_key": session_key,
    }


def load_entries(session) -> list:
    blob = load_local_vault_blob(session["username"])
    if blob is None:
        return []
    return decrypt_vault(session["dek"], blob)


def save_entries(session, entries: list):
    blob = encrypt_vault(session["dek"], entries)
    save_local_vault_blob(session["username"], blob)


def add_entry(session):
    entries = load_entries(session)
    site = input("Site/service name: ").strip()
    site_username = input("Username for that site: ").strip()
    site_password = getpass.getpass("Password to store: ")
    entries.append({"site": site, "username": site_username, "password": site_password})
    save_entries(session, entries)
    print("Entry added locally. Run 'sync' to push it to the server.")


def list_entries(session):
    entries = load_entries(session)
    if not entries:
        print("(vault is empty)")
        return
    for i, e in enumerate(entries):
        print(f"  [{i}] {e['site']}  -  user: {e['username']}  -  password: {e['password']}")


def sync_vault(session):
    """Upload the local vault: AES-encrypt under the DEK, RSA-sign, send to server."""
    entries = load_entries(session)
    blob = encrypt_vault(session["dek"], entries)
    save_local_vault_blob(session["username"], blob)
    signature = cu.rsa_sign(session["private_key"], blob)  # non-repudiation

    secure_send(session["sock"], session["session_key"], {
        "type": "upload_vault",
        "username": session["username"],
        "blob": cu.b64(blob),
        "signature": cu.b64(signature),
    })
    reply = secure_recv(session["sock"], session["session_key"])
    if reply.get("type") == "upload_ok":
        print("Vault synced to server.")
    else:
        print(f"Sync failed: {reply.get('message')}")


def fetch_and_verify_certificate(session, username):
    """Fetch a username's certificate from the server and verify it against
    our pinned CA key. Returns the verified public key, or None."""
    secure_send(session["sock"], session["session_key"], {"type": "get_certificate", "username": username})
    reply = secure_recv(session["sock"], session["session_key"])
    if reply.get("type") != "certificate":
        print(f"Could not fetch certificate: {reply.get('message')}")
        return None

    with open(CA_KEY_PATH, "r") as f:
        ca_public_key = cu.load_public_key(f.read().encode())

    if not cu.verify_certificate(ca_public_key, reply["username"], reply["public_key"], cu.unb64(reply["signature"])):
        print(f"WARNING: certificate for '{username}' does NOT verify against the CA key. Possible tampering.")
        return None

    print(f"Certificate for '{username}' verified against the CA key.")
    return cu.load_public_key(reply["public_key"].encode())


def pull_vault(session):
    """Download the vault from the server, verify the certificate for the
    signing key, verify the signature, then decrypt with the DEK."""
    verified_public_key = fetch_and_verify_certificate(session, session["username"])
    if verified_public_key is None:
        print("Aborting pull - could not confirm the server's stored public key is authentic.")
        return

    secure_send(session["sock"], session["session_key"], {
        "type": "download_vault",
        "username": session["username"],
    })
    reply = secure_recv(session["sock"], session["session_key"])
    if reply.get("type") != "vault_data":
        print(f"Pull failed: {reply.get('message')}")
        return

    blob = cu.unb64(reply["blob"])
    signature = cu.unb64(reply["signature"])
    if not cu.rsa_verify(verified_public_key, blob, signature):
        print("WARNING: signature verification failed - vault may be tampered with. Aborting.")
        return

    entries = decrypt_vault(session["dek"], blob)
    save_local_vault_blob(session["username"], blob)
    print(f"Pulled {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} from server (certificate + signature verified).")


def change_master_password(session):
    """Demonstrates why the DEK/KEK split exists: changing the master
    password only re-wraps the small DEK and re-encrypts the private key -
    the (potentially large) vault.enc file is never touched."""
    new_password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if new_password != confirm:
        print("Passwords did not match - no changes made.")
        return

    new_salt = cu.generate_salt()
    new_kek = cu.derive_key_from_password(new_password, new_salt)
    new_wrapped_dek = cu.aes_encrypt(new_kek, session["dek"])
    new_private_pem = cu.serialize_private_key(session["private_key"], password=new_password.encode())

    d = user_dir(session["username"])
    with open(os.path.join(d, "salt.bin"), "wb") as f:
        f.write(new_salt)
    with open(os.path.join(d, "wrapped_dek.bin"), "wb") as f:
        f.write(new_wrapped_dek)
    with open(os.path.join(d, "private_key.pem"), "wb") as f:
        f.write(new_private_pem)

    session["kek"] = new_kek
    session["salt"] = new_salt
    print("Master password changed. The vault itself was not re-encrypted - only the DEK wrapping was updated.")


# ---------------------------------------------------------------------------
# CLI loop
# ---------------------------------------------------------------------------

def main_menu():
    print("=== Password Manager ===")
    print("1) Register")
    print("2) Login")
    print("3) Quit")
    choice = input("> ").strip()

    if choice == "1":
        register()
        return True
    if choice == "2":
        session = login()
        if session:
            session_loop(session)
        return True
    if choice == "3":
        return False
    print("Invalid choice.")
    return True


def session_loop(session):
    print("\nCommands: add | list | sync | pull | passwd | logout")
    while True:
        cmd = input(f"({session['username']}) > ").strip().lower()
        if cmd == "add":
            add_entry(session)
        elif cmd == "list":
            list_entries(session)
        elif cmd == "sync":
            sync_vault(session)
        elif cmd == "pull":
            pull_vault(session)
        elif cmd == "passwd":
            change_master_password(session)
        elif cmd == "logout":
            secure_send(session["sock"], session["session_key"], {"type": "bye"})
            secure_recv(session["sock"], session["session_key"])
            session["sock"].close()
            print("Logged out.")
            break
        else:
            print("Unknown command. Use: add | list | sync | pull | passwd | logout")


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    while main_menu():
        pass