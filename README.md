# Encrypted-Chat

This project showcases a practical implementation of end-to-end encryption to establish a secure peer-to-peer communication channel using Python.

The application uses TLS/SSL for socket encryption, Elliptic Curve Diffie-Hellman (ECDH) for secure key exchange, HKDF-SHA384 for key derivation, and ChaCha20-Poly1305 for message encryption.

Forward secrecy is maintained by generating new key pairs for each message exchange, ensuring that the compromise of a single key does not jeopardize past or future communications.

## Usage

Clone the repository:
```
git clone https://github.com/phenotypic/Encrypted-Chat.git
```

Change to the project directory:
```
cd Encrypted-Chat
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
| `-p <port>` | Port: server listen port (defaults to `8000`) |
| `-t <ip>` | Target: target IP address |
| `-r <port>` | Remote: target port (defaults to `8000`) |
| `-k <path>` | Key: path to SSL private key file |
| `-c <path>` | Certificate: path to SSL certificate file |

After the target's IP and port have been determined, the script will generate self-signed SSL certificates (unless key/certificate files are passed as arguments) and attempt to establish a connection with the target. If this fails, the script will open a listen server and await a connection.

Once a secure TLS/SSL connection is established, the peers perform an [Elliptic Curve Diffie-Hellman (ECDH)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman) key exchange using the [NIST P-384](https://en.wikipedia.org/wiki/P-384) curve to generate ephemeral keys. The peers then pass their shared secret through a [HKDF-SHA384](https://en.wikipedia.org/wiki/HKDF) key derivation function to generate symmetric encryption keys. This process is repeated for each message to ensure [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy).

When a user submits a message, it is encrypted using [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305). The ciphertext is prefixed with its byte length and sent over the TLS/SSL connection. On the receiving end, the message is buffered, decrypted, and verified (to protect against message tampering).

**Note:** By default, the script generates self-signed SSL certificates. While these certificates offer the benefits of SSL/TLS encryption, they cannot be automatically verified since they are not issued by a recognised Certificate Authority. As such, it is important to manually validate your peer's public key hash using using out-of-band communication to protect against man-in-the-middle attacks.
