# P2P-E2E-Encryption-Chat

P2P-E2E-Encryption-Chat showcases a practical implementation of end-to-end encryption to establish a secure peer-to-peer communication channel.

The application uses Secure Sockets Layer (SSL) for socket encryption, Elliptic Curve Diffie-Hellman (ECDH) for secure key exchange, HKDF-SHA256 for key derivation, and AES-256-GCM for end-to-end message encryption.

## Installation

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

## Usage

| Flag | Description |
| --- | --- |
| `-i <ip>` | IP: server IP address (defaults to local IP) |
| `-p <port>` | Port: server listen port (defaults to 8000) |
| `-t <ip>` | Target: target IP address |
| `-r <port>` | Remote: target port (defaults to 8000) |
| `-m <mode>` | Mode: connection mode: hybrid (default) `0`, client `1`, server `2` |
| `-k <path>` | Key: path to SSL private key file |
| `-c <path>` | Certificate: path to SSL certificate file |
