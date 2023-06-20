import socket, threading, secrets, json, os, argparse, struct
from prettytable import PrettyTable
from pyfiglet import Figlet
from tinyec import registry, ec
from datetime import datetime
from base64 import b64encode, b64decode
from OpenSSL import crypto, SSL
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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

# Function to print the current date and time
def print_time():
    return datetime.now().strftime('%d/%m/%y %H:%M')

# Try to set the server address, defaulting to the local IP if no IP is provided
try:
    server_address = args.ip or socket.gethostbyname_ex(hostname)[-1][-1]
except:
    print('Error retrieving IP address from host name, please try again...')
    quit()
print(f'Target address: {server_address}:{args.port}')

# If no target IP is provided, ask the user to input it
if not args.target:
    target_ip, *target_port = input('Input target address: ').split(':')
    args.target = target_ip
    args.remote = target_port[0] if target_port else args.remote
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
        acting_server = False
    else:
        socket_connection.bind((server_address, args.port))
        socket_connection.listen(1)
        socket_connection, client_address = socket_connection.accept()
        print(f'\nServer received connection from: {client_address[0]} ({print_time()})')
        acting_server = True

    return socket_connection, acting_server

# Establish peer-to-peer connection
if args.mode in [0, 1]:
    try:
        main_socket, acting_server = create_socket_connection(secure_context, 'client')
    except socket.error:
        if args.mode == 0:
            print('\nTarget is not available, starting listening server on port', str(args.port) + '...')
            main_socket, acting_server = create_socket_connection(secure_context, 'server')
        elif args.mode == 1:
            print('\nTarget is not available, exiting...')
            quit()
else:
    main_socket, acting_server = create_socket_connection(secure_context, 'server')

print(line_print)

# ECC key serialisation
def send_key(key):
    data = {'x': str(key.x), 'y': str(key.y)}
    json_data = json.dumps(data).encode()
    return json_data

# ECC key deserialisation
def receive_key(json_data):
    data = json.loads(json_data.decode())
    key = ec.Point(curve, int(data['x']), int(data['y']))
    return key

# Display a hex representation of the ECC key
def hex_key(key):
    key_material = int.to_bytes(key.x, 32, 'big') + int.to_bytes(key.y, 32, 'big')
    return key_material.hex()

keys_table = PrettyTable(['Your public key', 'Peer\'s public key'], max_width=32)

# Get the curve
curve = registry.get_curve('brainpoolP256r1')

# Perform the ECDH key exchange
try:
    privKey = secrets.randbelow(curve.field.n)
    if acting_server:
        salt = os.urandom(16)
        pubKey = privKey * curve.g
        main_socket.send(salt + send_key(pubKey))
        ciphertextPubKey = receive_key(main_socket.recv(256))
        sharedECDHKey = ciphertextPubKey * privKey
        keys_table.add_row([hex_key(pubKey), hex_key(ciphertextPubKey)])
    else:
        received = main_socket.recv(256)
        salt = received[:16]
        pubKey = receive_key(received[16:])
        ciphertextPrivKey = secrets.randbelow(curve.field.n)
        ciphertextPubKey = ciphertextPrivKey * curve.g
        sharedECDHKey = pubKey * ciphertextPrivKey
        main_socket.send(send_key(ciphertextPubKey))
        keys_table.add_row([hex_key(ciphertextPubKey), hex_key(pubKey)])
except Exception as e:
    print('\nAn error occurred during the key exchange:', e)
    main_socket.close()
    quit()

print('Key exchange completed')
print('\nVerify public keys using out-of-band communication:')
print(keys_table)
print(line_print)

# Derive the AES key from the shared key
hkdf = HKDF(
    algorithm = hashes.SHA256(),
    length = 32,
    salt = salt,
    info = b'chat data',
)
key_material = int.to_bytes(sharedECDHKey.x, 32, 'big') + int.to_bytes(sharedECDHKey.y, 32, 'big')
aes_key = hkdf.derive(key_material)

# Print details about the encryption setup
print('Chat is now end-to-end encrypted:\n')
print('- Socket wrapper:                 Secure Sockets Layer (SSL)')
print('- Key exchange scheme:            Elliptic Curve Diffie-Hellman (ECDH)')
print('- Elliptic curve:                 brainpoolP256r1')
print('- Key derivation function:        HKDF-SHA256')
print('- Symmetric encryption algorithm: AES-256-GCM (Galois/Counter Mode)')
print('\nExit by typing /quit')
print(line_print)

# AES message encryption
def encrypt_message(message):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct_bytes = cipher.encrypt(message.encode())
    iv = b64encode(cipher.nonce).decode()
    ct = b64encode(ct_bytes).decode()
    tag = b64encode(cipher.digest()).decode()
    encrypted_message = json.dumps({'iv': iv, 'ciphertext': ct, 'tag': tag}).encode()
    # Prefix encrypted message with a 4-byte length (network byte order)
    result = struct.pack('>I', len(encrypted_message)) + encrypted_message
    return result

# AES message decryption
def decrypt_message(json_input):
    b64 = json.loads(json_input.decode())
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    tag = b64decode(b64['tag'])
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    plain_text = cipher.decrypt_and_verify(ct, tag)
    return plain_text.decode()

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

# Thread for sending messages
def thread_sending():
    while True:
        message_to_send = input('\nWrite a message: ')
        if message_to_send:
            try:
                main_socket.sendall(encrypt_message(message_to_send))
                print('Sent', print_time())
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
            message = decrypt_message(recv_msg())
            if message == '/quit':
                print('\n\nPeer left the chat, exiting...\n')
                main_socket.close()
                return
            print('\nReceived (' + print_time() + '):', message)
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
