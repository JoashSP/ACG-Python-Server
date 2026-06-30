Password Manager — Client/Server (ST2504 Assignment 2)
========================================================

REQUIREMENTS
  pip install cryptography

FILES
  crypto_utils.py  - KDF, AES-256-GCM, RSA encrypt/decrypt/sign/verify helpers
  network.py       - length-prefixed JSON message framing over TCP sockets
  server.py        - "dumb" storage server (never sees plaintext)
  client.py        - interactive CLI password manager

HOW TO RUN
  Terminal 1:
    python3 server.py
    (listens on 127.0.0.1:5050)

  Terminal 2:
    python3 client.py
    Menu options:
      1) Register   - creates an RSA keypair + local encrypted vault,
                       registers your public key + PBKDF2 salt with the server
      2) Login      - unlocks your local private key with your master
                       password, then proves possession of it to the server
                       via an RSA-signed challenge (no password sent over
                       the network)

    Once logged in:
      add     - add a new site/username/password entry to your local vault
      list    - show your current vault entries
      sync    - AES-encrypt the vault, RSA-sign it, upload to the server
      pull    - download the vault from the server, verify the RSA
                signature, then AES-decrypt it (use this on a second
                "device" / client_data folder to test multi-device sync)
      logout  - close the session

WHERE THE CRYPTOGRAPHY IS USED
  - PBKDF2-HMAC-SHA256 : derives the vault key from your master password
  - AES-256-GCM        : encrypts the vault at rest, and encrypts every
                          message sent over the network during a session
  - RSA-OAEP           : wraps the AES session key when the connection
                          is first established (key transport)
  - RSA-PSS signatures : (1) prove possession of the private key during
                          login (authentication) and (2) sign every vault
                          upload so the server (or another client) can
                          verify who produced it (non-repudiation)

LOCAL DATA LAYOUT (created automatically)
  client_data/<username>/private_key.pem   - password-encrypted RSA private key
  client_data/<username>/public_key.pem
  client_data/<username>/salt.bin
  client_data/<username>/vault.enc         - AES-GCM encrypted vault cache
  server_db.json                            - server-side store (public keys,
                                               salts, encrypted vault blobs,
                                               signatures only — no plaintext)

TO SIMULATE TWO DEVICES
  Run the client from two different working directories (or rename
  client_data) so each has its own local cache, register/login as the
  same user is not needed — just register two different usernames, or
  copy one user's client_data folder to a second location, log in there,
  and run "pull" to fetch the synced vault.