import socket, os, argparse, struct, json, base64, threading, queue, ssl
from datetime import datetime, timezone
from prettytable import PrettyTable
from pyfiglet import Figlet
from termcolor import colored
from datetime import datetime
from hashlib import sha256
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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

def print_time(resolution):
    if resolution == 'minutes':
        return datetime.now().strftime('%H:%M')
    elif resolution == 'date':
        return datetime.now().strftime('%d/%m/%Y %H:%M:%S')

try:
    server_address = args.ip or socket.gethostbyname_ex(hostname)[-1][-1]
except:
    print('Error retrieving IP address from host name, please try again...')
    quit()
print(f'Local host address: {server_address}:{args.port}')

if not args.target:
    target_ip, *target_port = input('Input target address: ').split(':')
    args.target = target_ip
    args.remote = int(target_port[0]) if target_port else args.remote
print(f'Target address: {args.target}:{args.remote}')

# Set up SSL context using standard ssl module
secure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
secure_context.verify_mode = ssl.CERT_NONE  # Since we're using self-signed certificates

def create_self_signed_cert():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc).replace(day=datetime.now(timezone.utc).day + 5)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Serialize private key and certificate
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    
    return private_key_bytes, cert_bytes

if args.key and args.cert:
    # Use provided key and certificate
    secure_context.load_cert_chain(args.cert, args.key)
else:
    # Generate new self-signed certificate
    private_key_bytes, cert_bytes = create_self_signed_cert()
    
    # Write temporary files for the SSL context
    temp_key_path = 'temp_key.pem'
    temp_cert_path = 'temp_cert.pem'
    
    with open(temp_key_path, 'wb') as f:
        f.write(private_key_bytes)
    with open(temp_cert_path, 'wb') as f:
        f.write(cert_bytes)
    
    secure_context.load_cert_chain(temp_cert_path, temp_key_path)
    
    # Clean up temporary files
    os.remove(temp_key_path)
    os.remove(temp_cert_path)

# Establish peer-to-peer connection
try:
    main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # For client mode, use different SSL context
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    main_socket = client_context.wrap_socket(main_socket)
    main_socket.connect((args.target, args.remote))
    print(f'\nConnected as a client to: {main_socket.getsockname()[0]} ({print_time("date")})')
    initiate_handshake = False
except socket.error:
    print(f'\nTarget is not available, starting listening server on port {args.port}...')
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_address, args.port))
    server_socket.listen(1)
    client_socket, client_address = server_socket.accept()
    main_socket = secure_context.wrap_socket(
        client_socket,
        server_side=True
    )
    print(f'\nServer received connection from: {client_address[0]} ({print_time("date")})')
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
        return b''
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
    return derive_key(shared_secret, salt, b'encryption key')

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
    encrypted_message = aead_cipher.encrypt(nonce, message, None)
    return nonce + encrypted_message

# Decryption function. Accepts an encrypted message (bytes) and a key, returns plaintext (bytes)
def decrypt(encrypted_message, key):
    aead_cipher = ChaCha20Poly1305(key)
    nonce = encrypted_message[:12]
    return aead_cipher.decrypt(nonce, encrypted_message[12:], None)

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
    construct = json.dumps(construct).encode()

    # Encrypt the message
    encrypted_message = encrypt(bytes([0x00]) + construct, encryption_key)
    send_bytes(encrypted_message)

    # Derive sub-key to handle DH response
    encryption_key = derive_key(encryption_key, sub_salt, b'sub-key')

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
    encryption_key = derive_key(encryption_key, sub_salt, b'sub-key')

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
            except ssl.SSLError:
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
        except ssl.SSLError:
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
