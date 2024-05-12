import socket, os, argparse, struct, json, base64, threading, queue
from prettytable import PrettyTable
from pyfiglet import Figlet
from termcolor import colored
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
parser.add_argument('-k', '--key', type=str, help='path to SSL private key file')
parser.add_argument('-c', '--cert', type=str, help='path to SSL certificate file')
args = parser.parse_args()

hostname = socket.gethostname()

print('\n\n' + Figlet(font='big', justify='center').renderText('P2P Chat'))
line_print = '-' * os.get_terminal_size().columns
print(line_print)

# Function to print the current time
def print_time(resolution):
    if resolution == 'minutes':
        return datetime.now().strftime('%H:%M')
    elif resolution == 'date':
        return datetime.now().strftime('%d/%m/%Y %H:%M:%S')

# Try to set the server address, defaulting to the local IP if no IP is provided
try:
    server_address = args.ip or socket.gethostbyname_ex(hostname)[-1][-1]
except:
    print('Error retrieving IP address from host name, please try again...')
    quit()
print(f'Local host address: {server_address}:{args.port}')

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

# Establish peer-to-peer connection
try:
    main_socket = SSL.Connection(secure_context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    main_socket.connect((args.target, args.remote))
    print(f'\nConnected as a client to: {main_socket.getsockname()[0]} ({print_time('date')})')
    initiate_handshake = False
except socket.error:
    print(f'\nTarget is not available, starting listening server on port {args.port}...')
    main_socket = SSL.Connection(secure_context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    main_socket.bind((server_address, args.port))
    main_socket.listen(1)
    main_socket, client_address = main_socket.accept()
    print(f'\nServer received connection from: {client_address[0]} ({print_time('date')})')
    initiate_handshake = True

print(line_print)

# Helper function to send bytes with a 4-byte length prefix (network byte order)
def send_bytes(message):
    result = struct.pack('>I', len(message)) + message
    main_socket.sendall(result)

# Helper function to receive bytes with a 4-byte length prefix (network byte order)
def recv_bytes():
    # Read message length and unpack it into an integer
    raw_msglen = recvall(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(msglen)

# Subfunction to receive all bytes for a given length
def recvall(n):
    data = bytearray()
    while len(data) < n:
        packet = main_socket.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    
    # Serialize the public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key_bytes

def get_encryption_key(private_key, peer_public_key_bytes, salt):
    # Deserialize the peer's public key
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_bytes,
        backend=default_backend()
    )

    # Derive the shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive the encryption key
    return derive_key(shared_secret, salt, info=b'encryption key')

def derive_key(key_material, salt, info):
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(key_material)

# Generate key pair
private_key, public_key_bytes = generate_key_pair()

# Exchange random salt and public keys
if initiate_handshake:
    salt = os.urandom(16)
    send_bytes(salt + public_key_bytes)
    peer_public_key_bytes = recv_bytes()
else:
    received = recv_bytes()
    salt = bytes(received[:16])
    peer_public_key_bytes = received[16:]
    send_bytes(public_key_bytes)

# Derive the encryption key
encryption_key = get_encryption_key(private_key, peer_public_key_bytes, salt)

# Print the public keys
print(f'Key exchange completed ({print_time('date')})')
print('\nVerify public key hashes using out-of-band communication:')
keys_table = PrettyTable(['Your Public Key Hash', 'Peer\'s Public Key Hash'], max_width=32)
keys_table.add_row([sha256(public_key_bytes).hexdigest(), sha256(peer_public_key_bytes).hexdigest()])
print(keys_table)
print(line_print)

# Print details about the encryption setup
print(f'Chat started: {print_time("date")}\n')
print('- Socket wrapper  : Secure Sockets Layer (SSL)')
print('- Key exchange    : Elliptic Curve Diffie-Hellman (ECDH)')
print('- Elliptic curve  : NIST P-384 (secp384r1)')
print('- Key derivation  : HKDF-SHA384')
print('- Encryption      : ChaCha20-Poly1305')
print('- Forward secrecy : Enabled for each message')
print('\nExit by typing /quit')
print(line_print)

# Encryption function. Accepts a message (bytes) and a key, returns encrypted message (bytes)
def encrypt(message, key):
    # Encrypt the message using the derived key
    aead_cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    encrypted_message = aead_cipher.encrypt(nonce, message)
    encrypted_message = nonce + encrypted_message
    return encrypted_message

# Decryption function. Accepts an encrypted message (bytes) and a key, returns plaintext (bytes)
def decrypt(encrypted_message, key):
    aead_cipher = ChaCha20Poly1305(key)
    nonce = encrypted_message[:12]
    plaintext = aead_cipher.decrypt(nonce, encrypted_message[12:])
    return plaintext

def send_encrypted_message(message):
    global encryption_key

    # Generate a new key pair and salt
    private_key, public_key_bytes = generate_key_pair()
    salt = os.urandom(16)

    # Sub-salt for sub-key
    sub_salt = os.urandom(16)

    # Construct JSON object
    construct = {
        'message': message,
        'salt': base64.b64encode(salt).decode(),
        'key': base64.b64encode(public_key_bytes).decode(),
        'sub_salt': base64.b64encode(sub_salt).decode()
    }
    construct = json.dumps(construct)

    # Encrypt the message
    encrypted_message = encrypt(bytes([0x00]) + construct.encode(), encryption_key)
    send_bytes(encrypted_message)

    # Derive sub-key to handle DH response
    encryption_key = derive_key(encryption_key, sub_salt, info=b'sub-key')

    # Receive the public key (already decrypted by the time this is called)
    peer_public_key_bytes = message_queue.get()

    # Derive the encryption key
    encryption_key = get_encryption_key(private_key, peer_public_key_bytes, salt)

def recv_encrypted_message():
    global encryption_key

    # Receive the message
    encrypted_message = recv_bytes()

    # Decrypt the message
    incoming_message = decrypt(encrypted_message, encryption_key)

    # Parse the message
    message_type = incoming_message[0]
    message = incoming_message[1:]

    # Handle the message if it is a DH public key response
    if message_type == 0x01:
        message_queue.put(message)
        return None

    # Generate a new key pair
    private_key, public_key_bytes = generate_key_pair()

    # Parse the JSON object
    construct = json.loads(message.decode())
    message = construct['message']
    salt = base64.b64decode(construct['salt'])
    peer_public_key_bytes = base64.b64decode(construct['key'])
    sub_salt = base64.b64decode(construct['sub_salt'])

    # Derive sub-key to handle DH response
    encryption_key = derive_key(encryption_key, sub_salt, info=b'sub-key')

    # Send the public key using the sub-key
    send_bytes(encrypt(bytes([0x01]) + public_key_bytes, encryption_key))

    # Derive the encryption key
    encryption_key = get_encryption_key(private_key, peer_public_key_bytes, salt)

    return message

# Thread for sending messages
def thread_sending():
    while True:
        message = input('\nWrite a message: ')
        if message:
            try:
                send_encrypted_message(message)
                print(f'\033[F\33[2K\rSent {print_time('minutes')}: {colored(message, attrs=["bold"])}')
                if message == '/quit':
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
            # Receive the message
            message = recv_encrypted_message()
            if message is not None:
                if message == '/quit':
                    print('\n\nPeer left the chat, exiting...\n')
                    main_socket.close()
                    return
                print(f'\033[F\33[2K\r\nReceived {print_time('minutes')}: {colored(message, attrs=["bold"])}')
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

# Create a message queue
message_queue = queue.Queue()
