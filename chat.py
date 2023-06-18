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
parser.add_argument('-p', '--port', type=int, help='server listen port (defaults to 8000)', default=8000, nargs='?')
parser.add_argument('-t', '--target', type=str, help='target IP address')
parser.add_argument('-r', '--remote', type=int, help='target port (defaults to 8000)', default=8000, nargs='?')
parser.add_argument('-m', '--mode', help='connection mode: automatic (default) 0, client 1 server 2', default=0, nargs='?', choices=[0, 1, 2])
parser.add_argument('-k', '--key', type=str, help='path to SSL private key file')
parser.add_argument('-c', '--cert', type=str, help='path to SSL certificate file')
args = parser.parse_args()

f = Figlet(font='big')
print('\n\n' + f.renderText('P2P Chat'))

hostname = socket.gethostname()

print('-'*71)
server_address = args.ip if args.ip else socket.gethostbyname_ex(hostname)[-1][-1]
print('Server address:', server_address + ':' + str(args.port))

if args.target:
    target_address = args.target
else:
    full_answer = input('Input target address: ').split(':')
    target_address = full_answer[0]
    args.remote = full_answer[1] if len(full_answer[1]) > 1 else args.remote
print('Target address:', target_address + ':' + str(args.remote))

def print_time():
    return datetime.now().strftime('%d/%m/%y %H:%M')

ctx = SSL.Context(SSL.TLS_METHOD)
if args.key and args.cert:
    # Use user-specified key and certificate
    ctx.use_privatekey_file(args.key)
    ctx.use_certificate_file(args.cert)
else:
    # Generate SSL key pair
    keypair = crypto.PKey()
    keypair.generate_key(crypto.TYPE_RSA, 2048)

    # Create SSL self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = hostname
    cert.set_issuer(cert.get_subject())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5*24*60*60) # Valid for 5 days
    cert.set_pubkey(keypair)
    cert.sign(keypair, 'sha256')

    # Initialise SSL context
    ctx.use_privatekey(keypair)
    ctx.use_certificate(cert)

# Define client socket connection
def client_connect():
    main_socket = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    main_socket.connect((target_address, args.remote))
    print('\nConnected as a client to:', main_socket.getsockname()[0], '(' + print_time() + ')')
    return main_socket, False

# Define server socket connection
def server_connect():
    main_socket = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    main_socket.bind((server_address, args.port))
    main_socket.listen(1)
    main_socket, client_address = main_socket.accept()
    print('Server received connection from:', client_address[0], '(' + print_time() + ')')
    return main_socket, True

# Establish a socket connection
if args.mode in [0, 1]:
    try:
        main_socket, acting_server = client_connect()
    except socket.timeout:
        print('\nConnection timed out., quitting...')
        quit()
    except socket.error:
        if args.mode == 0:
            print('\nTarget is not available, starting listening server on port', str(args.port) + '...')
            main_socket, acting_server = server_connect()
        elif args.mode == 1:
            print('\nTarget is not available, exiting...')
            quit()
else:
    main_socket, acting_server = server_connect()

print('-'*71)

# ECC key serialisation
def send_key(key):
    data = {"x": str(key.x), "y": str(key.y)}
    json_data = json.dumps(data).encode()
    return json_data

# ECC key deserialisation
def receive_key(json_data):
    data = json.loads(json_data.decode())
    key = ec.Point(curve, int(data["x"]), int(data["y"]))
    return key

def hex_key(key):
    key_material = int.to_bytes(key.x, 32, 'big') + int.to_bytes(key.y, 32, 'big')
    return key_material.hex()

list = PrettyTable(['Your public key', 'Peer\'s public key'], max_width=32)

# Get the curve
curve = registry.get_curve('brainpoolP256r1')

# Perform the ECDH key exchange
try:
    privKey = secrets.randbelow(curve.field.n)
    if acting_server:
        pubKey = privKey * curve.g
        main_socket.send(send_key(pubKey))
        ciphertextPubKey = receive_key(main_socket.recv(256))
        sharedECDHKey = ciphertextPubKey * privKey
        salt = os.urandom(16)
        main_socket.send(salt)
        list.add_row([hex_key(pubKey), hex_key(ciphertextPubKey)])
    else:
        pubKey = receive_key(main_socket.recv(256))
        ciphertextPrivKey = secrets.randbelow(curve.field.n)
        ciphertextPubKey = ciphertextPrivKey * curve.g
        sharedECDHKey = pubKey * ciphertextPrivKey
        main_socket.send(send_key(ciphertextPubKey))
        salt = main_socket.recv(16)
        list.add_row([hex_key(ciphertextPubKey), hex_key(pubKey)])
except Exception as e:
    print('\nAn error occurred during the key exchange:', e)
    main_socket.close()
    quit()

print('Key exchange completed')
print('\nVerify public keys using out-of-band communicaiton:')
print(list)
print('-'*71)

# Derive the AES key from the shared key
hkdf = HKDF(
    algorithm = hashes.SHA256(),
    length = 32,
    salt = salt,
    info = b'chat data',
)
key_material = int.to_bytes(sharedECDHKey.x, 32, 'big') + int.to_bytes(sharedECDHKey.y, 32, 'big')
aes_key = hkdf.derive(key_material)

print('Chat is now end-to-end encrypted:\n')
print('- Socket wrapper:                 Secure Sockets Layer (SSL)')
print('- Key exchange scheme:            Elliptic Curve Diffie-Hellman (ECDH)')
print('- Elliptic curve:                 brainpoolP256r1')
print('- Key derivation function:        HKDF-SHA256')
print('- Symmetric encryption algorithm: AES-256-GCM (Galois/Counter Mode)')
print('\nExit by typing /quit')
print('-'*71)

# AES encrypt of message
def encrypt_message(message):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct_bytes = cipher.encrypt(message.encode())
    iv = b64encode(cipher.nonce).decode()
    ct = b64encode(ct_bytes).decode()
    tag = b64encode(cipher.digest()).decode()
    result = json.dumps({'iv': iv, 'ciphertext': ct, 'tag': tag})
    return result.encode()

# AES decrypt of message
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
                encrypted_message = encrypt_message(message_to_send)
                # Prefix each message with a 4-byte length (network byte order)
                prefixed_message = struct.pack('>I', len(encrypted_message)) + encrypted_message
                main_socket.sendall(prefixed_message)
                print('Sent', print_time())
                if message_to_send == '/quit':
                    print('\nEnding the chat...')
                    main_socket.close()
                    return
            except SSL.SysCallError:
                print('sending connection broke')
                return
            except Exception as e:
                print('\nAn error occurred in message sending:', e)
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
            print('\nConnection broke, quitting...\n')
            main_socket.close()
            return
        except Exception as e:
            print('\nAn error while handling a message:', e)
            main_socket.close()
            return

# Create threads
thread_send = threading.Thread(target=thread_sending)
thread_send.daemon = True
thread_receive = threading.Thread(target=thread_receiving)
thread_send.start()
thread_receive.start()
