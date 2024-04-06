import socket, threading, os, argparse, struct
from prettytable import PrettyTable
from pyfiglet import Figlet
from datetime import datetime
from hashlib import sha256
from OpenSSL import crypto, SSL
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip', type=str, help='server IP address (defaults to local IP)')
parser.add_argument('-p', '--port', type=int, help='server listen port (defaults to 8000)', default=8000)
parser.add_argument('-t', '--target', type=str, help='target IP address')
parser.add_argument('-r', '--remote', type=int, help='target port (defaults to 8000)', default=8000)
parser.add_argument('-m', '--mode', choices=[0, 1, 2], help='connection mode: automatic (default) 0, client 1 server 2', default=0)
parser.add_argument('-k', '--key', type=str, help='path to SSL private key file')
parser.add_argument('-c', '--cert', type=str, help='path to SSL certificate file')
args = parser.parse_args()

hostname = socket.gethostname()

print('\n\n' + Figlet(font='big', justify='center').renderText('P2P Chat'))
line_print = '-' * os.get_terminal_size().columns
print(line_print)

# Function to print the current time
def print_time():
    return datetime.now().strftime('%H:%M')

# Try to set the server address, defaulting to the local IP if no IP is provided
try:
    server_address = args.ip or socket.gethostbyname_ex(hostname)[-1][-1]
except:
    print('Error retrieving IP address from host name, please try again...')
    quit()
print(f'Host address: {server_address}:{args.port}')

# If no target IP is provided, ask the user to input it
if not args.target:
    target_ip, *target_port = input('Input target address: ').split(':')
    args.target = target_ip
    args.remote = int(target_port[0]) if target_port else args.remote
print(f'Target address: {args.target}:{args.remote}')

# Set up SSL context
secure_context = SSL.Context(SSL.TLS_METHOD)

# Fucntion to generate a new RSA key pair and create a self-signed certificate
def create_self_signed_cert():
    keypair = crypto.PKey()
    keypair.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = hostname
    cert.set_issuer(cert.get_subject())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5*24*60*60)  # Certificate is valid for 5 days
    cert.set_pubkey(keypair)
    cert.sign(keypair, 'sha256')

    return keypair, cert

if args.key and args.cert:
    # Use the provided key and certificate
    secure_context.use_privatekey_file(args.key)
    secure_context.use_certificate_file(args.cert)
else:
    # No key and certificate provided, generate a new self-signed certificate
    keypair, cert = create_self_signed_cert()
    secure_context.use_privatekey(keypair)
    secure_context.use_certificate(cert)

# Create a new SSL socket connection
def create_socket_connection(context, connection_type):
    socket_connection = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    if connection_type == 'client':
        socket_connection.connect((args.target, args.remote))
        print(f'\nConnected as a client to: {socket_connection.getsockname()[0]} ({print_time()})')
        handshake_initiator = False
    else:
        socket_connection.bind((server_address, args.port))
        socket_connection.listen(1)
        socket_connection, client_address = socket_connection.accept()
        print(f'\nServer received connection from: {client_address[0]} ({print_time()})')
        handshake_initiator = True

    return socket_connection, handshake_initiator

# Establish peer-to-peer connection
if args.mode in [0, 1]:
    try:
        main_socket, handshake_initiator = create_socket_connection(secure_context, 'client')
    except socket.error:
        if args.mode == 0:
            print(f'\nTarget is not available, starting listening server on port {args.port}...')
            main_socket, handshake_initiator = create_socket_connection(secure_context, 'server')
        elif args.mode == 1:
            print('\nTarget is not available, exiting...')
            quit()
else:
    main_socket, handshake_initiator = create_socket_connection(secure_context, 'server')

print(line_print)

def recv_msg():
    # Read message length and unpack it into an integer
    raw_msglen = recvall(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(msglen)

# Helper function to recv n bytes or return None if EOF is hit
def recvall(n):
    data = bytearray()
    while len(data) < n:
        packet = main_socket.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

# Derive encryption key from shared secret
def derive_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

# Function to exchange keys
def exchange_keys(handshake_initiator):
    # Generate key pair
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    # Serialize the public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Exchange random salt and public keys
    if handshake_initiator:
        salt = os.urandom(16)
        combined_salt_pubkey = salt + public_key_bytes
        main_socket.sendall(struct.pack('>I', len(combined_salt_pubkey)) + combined_salt_pubkey)
        peer_public_key_bytes = recv_msg()
    else:
        received = recv_msg()
        salt = received[:16]
        peer_public_key_bytes = received[16:]
        result = struct.pack('>I', len(public_key_bytes)) + public_key_bytes
        main_socket.sendall(result)

    # Deserialize the peer's public key
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_bytes,
        backend=default_backend()
    )

    # Derive the encryption key
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    encryption_key = derive_key(shared_secret)
    return encryption_key, public_key_bytes, peer_public_key_bytes

# Exchange keys
encryption_key, public_key_bytes, peer_public_key_bytes = exchange_keys(handshake_initiator)

# Print the public keys
print('Key exchange completed')
print('\nVerify public keys using out-of-band communication:')
keys_table = PrettyTable(['Your public key', 'Peer\'s public key'], max_width=32)
keys_table.add_row([sha256(public_key_bytes).hexdigest(), sha256(peer_public_key_bytes).hexdigest()])
print(keys_table)
print(line_print)

# Print details about the encryption setup
print('Chat is now end-to-end encrypted:\n')
print('- Socket wrapper:                 Secure Sockets Layer (SSL)')
print('- Key exchange scheme:            Elliptic Curve Diffie-Hellman (ECDH)')
print('- Elliptic curve:                 brainpoolP256r1')
print('- Key derivation function:        HKDF-SHA384')
print('- Symmetric encryption algorithm: ChaCha20-Poly1305')
print('\nExit by typing /quit')
print(line_print)

# Encryption function
def encrypt(message, key):
    # Encrypt the message using the derived key
    aead_cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    encrypted_message = aead_cipher.encrypt(nonce, message.encode())
    encrypted_message = nonce + encrypted_message
    # Prefix encrypted message with a 4-byte length (network byte order)
    result = struct.pack('>I', len(encrypted_message)) + encrypted_message
    return result

# Decryption function
def decrypt(encrypted_message, key):
    aead_cipher = ChaCha20Poly1305(key)
    nonce = encrypted_message[:12]
    plaintext = aead_cipher.decrypt(nonce, encrypted_message[12:]).decode()
    return plaintext

# Thread for sending messages
def thread_sending():
    while True:
        message_to_send = input('\nWrite a message: ')
        if message_to_send:
            try:
                main_socket.sendall(encrypt(message_to_send, encryption_key))
                print(f'Sent ({print_time()}): {message_to_send}')
                if message_to_send == '/quit':
                    print('\nEnding the chat...')
                    main_socket.close()
                    return
            except SSL.SysCallError:
                print('Sending connection broke')
                return
            except Exception as e:
                print('\nAn error occurred while sending a message:', e)
                main_socket.close()
                return

# Thread for receiving messages
def thread_receiving():
    while True:
        try:
            message = decrypt(recv_msg(), encryption_key)
            if message == '/quit':
                print('\n\nPeer left the chat, exiting...\n')
                main_socket.close()
                return
            print(f'\nReceived ({print_time()}): {message}')
            print('\nWrite a message: ', end='')
        except SSL.SysCallError:
            print('\nConnection broke, exiting...\n')
            main_socket.close()
            return
        except Exception as e:
            print('\nAn error occurred while handling a message:', e)
            main_socket.close()
            return

# Create threads
thread_send = threading.Thread(target=thread_sending)
thread_send.daemon = True
thread_receive = threading.Thread(target=thread_receiving)
thread_send.start()
thread_receive.start()
