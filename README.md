# P2P-E2E-Encryption-Chat

P2P-E2E-Encryption-Chat showcases a practical implementation of end-to-end encryption to establish a secure peer-to-peer communication channel.

The application uses Secure Sockets Layer (SSL) for socket encryption, Elliptic Curve Diffie-Hellman (ECDH) for secure key exchange, HKDF-SHA256 for key derivation, AES-256-GCM for end-to-end message encryption, .

## Usage

Clone the repository:
```
git clone https://github.com/phenotypic/P2P-E2E-Encryption-Chat.git
```

Change to the project directory:
```
cd P2P-E2E-Encryption-Chat
```

Install dependencies:
```
pip3 install -r requirements.txt
```

Run the script:
```
python3 chat.py
```

Here are some flags you can add:

| Flag | Description |
| --- | --- |
| `-i <ip>` | IP: server IP address (defaults to local IP) |
| `-p <port>` | Port: server listen port (defaults to 8000) |
| `-t <ip>` | Target: target IP address |
| `-r <port>` | Remote: target port (defaults to 8000) |
| `-m <mode>` | Mode: connection mode: hybrid (default) `0`, client `1`, server `2` |
| `-k <path>` | Key: path to SSL private key file |
| `-c <path>` | Certificate: path to SSL certificate file |

After the target's IP and port have been determined, the script will generate self-signed SSL certificates (unless key/certificate files are passed as arguments) and attempt to establish a connection with the target. If this fails, the script will open a listen server and await a connection.

Once a secure connection is established, the peers perform an [Elliptic Curve Diffie-Hellman (ECDH)](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption) key exchange using the [`brainpoolP256r1`](https://herongyang.com/EC-Cryptography/Curve-brainpoolP256r1-for-256-Bit-ECC-Keys.html) curve. Once the key exchange has completed, users should compare the public keys using out-of-band communication where possible to protect against man-in-the-middle (MITM) attacks.

The peers then pass their shared eliptic curve key through a [HKDF-SHA256 ](https://en.wikipedia.org/wiki/HKDF) key derivation function to generate symmetric AES encryption keys. Once a message is submitted by either user, it is encrypted using AES-256 in [Galois/Counter Mode (GCM)](https://en.wikipedia.org/wiki/Galois/Counter_Mode). The cyphertext is then serialised into a JSON alongside its initialisaiton vector and authenticaiton tag, prefixed with its byte length, and sent over the SSL connection. On the recieving end, the message is buffered, deserialised, decrypted, and verified (to protect against message tampering).

## Notes

- The script generates a self-signed SSL certificate if no certificate is provided. While this fine for testing, it's not secure for a production environment as it can be exploited by MITM attacks. Use certificates signed by trusted Certificate Authorities (CAs) where possible and always validate your peer's public key
