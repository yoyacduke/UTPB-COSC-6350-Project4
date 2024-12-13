# [Previous imports remain the same]
import socket
import secrets
import hashlib
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# [WPA3Device class remains unchanged]
class WPA3Device:
    def __init__(self, is_ap=False):
        self.is_ap = is_ap
        print(f"\n{'AP' if is_ap else 'Client'} - Generating EC key pair...")
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        print(f"{'AP' if is_ap else 'Client'} - Private key created: {self.private_key.private_numbers().private_value % 100000}")
        print(f"{'AP' if is_ap else 'Client'} - Public key created: {self.public_key.public_numbers().x % 100000}")
        self.pmk = None
        self.ptk = None
        self.anonce = None
        self.snonce = None
    
    def generate_nonce(self):
        nonce = secrets.token_bytes(32)
        print(f"{'AP' if self.is_ap else 'Client'} - Generated nonce: {binascii.hexlify(nonce[:8]).decode()}...")
        return nonce
    
    def derive_pmk(self, password, ssid):
        print(f"\n{'AP' if self.is_ap else 'Client'} - Deriving PMK using password and SSID...")
        salt = ssid.encode('utf-8')
        self.pmk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            4096,
            32
        )
        print(f"{'AP' if self.is_ap else 'Client'} - PMK derived: {binascii.hexlify(self.pmk[:8]).decode()}...")
        
    def derive_ptk(self, anonce, snonce, ap_mac, sta_mac):
        print(f"\n{'AP' if self.is_ap else 'Client'} - Deriving PTK...")
        if not self.pmk:
            raise ValueError("PMK not yet derived")
            
        data = min(ap_mac, sta_mac) + max(ap_mac, sta_mac) + \
               min(anonce, snonce) + max(anonce, snonce)
               
        self.ptk = hashlib.pbkdf2_hmac(
            'sha384',
            self.pmk,
            data,
            100,
            48
        )
        print(f"{'AP' if self.is_ap else 'Client'} - PTK derived: {binascii.hexlify(self.ptk[:8]).decode()}...")
        
    def encrypt_message(self, message, iv=None):
        if not self.ptk:
            raise ValueError("PTK not yet derived")
            
        if iv is None:
            iv = secrets.token_bytes(16)
            
        key = self.ptk[:32]
        print(f"\n{'AP' if self.is_ap else 'Client'} - Encrypting message using AES key: {binascii.hexlify(key[:8]).decode()}...")
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        print(f"{'AP' if self.is_ap else 'Client'} - Message encrypted: {binascii.hexlify(ciphertext[:16]).decode()}...")
        return iv + ciphertext
        
    def decrypt_message(self, encrypted_data):
        if not self.ptk:
            raise ValueError("PTK not yet derived")
            
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        key = self.ptk[:32]
        print(f"\n{'AP' if self.is_ap else 'Client'} - Decrypting message using AES key: {binascii.hexlify(key[:8]).decode()}...")
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        decoded = plaintext.decode()
        print(f"{'AP' if self.is_ap else 'Client'} - Message decrypted: {decoded}")
        return decoded

class WPA3Server:
    def __init__(self, host='localhost', port=12345):
        print("\n=== Initializing WPA3 Access Point ===")
        self.host = host
        self.port = port
        self.device = WPA3Device(is_ap=True)
        self.ssid = "TestNetwork"
        self.password = "TestPassword123"
        print(f"\nAP - Using SSID: {self.ssid}")
        print(f"AP - Using password: {self.password}")
        self.device.derive_pmk(self.password, self.ssid)
        self.ap_mac = b'\x00\x11\x22\x33\x44\x55'
        print(f"AP - MAC Address: {binascii.hexlify(self.ap_mac).decode()}")
        
    def start(self):
        print("\n=== Starting TCP Server ===")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"TCP Server - Listening on {self.host}:{self.port}")
        print("TCP Server - Waiting for TCP 3-way handshake...")
        
        while True:
            print("\nTCP Server - Ready to accept connections")
            # TCP 3-way handshake starts here
            client_socket, addr = server_socket.accept()
            print(f"TCP Server - Received SYN from {addr}")
            print("TCP Server - Sent SYN-ACK")
            print(f"TCP Server - Received ACK from {addr}")
            print("=== TCP 3-way Handshake Completed ===\n")
            
            print("Starting WPA3 4-way handshake...")
            self.handle_client(client_socket)
            
    def handle_client(self, client_socket):
        try:
            print("\n=== Starting WPA3 Handshake (AP Side) ===")
            
            # WPA3 Message 1
            print("\nWPA3 Message 1: ANonce Generation and Exchange")
            self.device.anonce = self.device.generate_nonce()
            client_socket.send(self.device.anonce)
            print("AP - ANonce sent to client")
            
            # WPA3 Message 2
            print("\nWPA3 Message 2: SNonce Reception")
            self.device.snonce = client_socket.recv(32)
            print("AP - Received SNonce from client")
            
            sta_mac = client_socket.recv(6)
            print(f"AP - Client MAC received: {binascii.hexlify(sta_mac).decode()}")
            
            # WPA3 Message 3
            print("\nWPA3 Message 3: PTK Derivation and First Encrypted Message")
            self.device.derive_ptk(
                self.device.anonce,
                self.device.snonce,
                self.ap_mac,
                sta_mac
            )
            test_message = "WPA3 Handshake completed successfully! This is a test message from the AP."
            print(f"AP - Sending encrypted message: {test_message}")
            encrypted = self.device.encrypt_message(test_message)
            client_socket.send(encrypted)
            
            # WPA3 Message 4
            print("\nWPA3 Message 4: Receiving Client's Encrypted Response")
            encrypted_response = client_socket.recv(1024)
            decrypted = self.device.decrypt_message(encrypted_response)
            print("=== WPA3 4-way Handshake Completed ===\n")
            
            # Additional message exchange
            print("\nStarting Post-Handshake Communication")
            for i in range(3):
                message = f"AP Test Message #{i+1}: The connection is secure!"
                print(f"\nAP - Sending message: {message}")
                encrypted = self.device.encrypt_message(message)
                client_socket.send(encrypted)
                
                encrypted_response = client_socket.recv(1024)
                decrypted = self.device.decrypt_message(encrypted_response)
            
        except Exception as e:
            print(f"AP - Error during handshake: {e}")
        finally:
            client_socket.close()
            print("\nAP - Connection closed")

class WPA3Client:
    def __init__(self, host='localhost', port=12345):
        print("\n=== Initializing WPA3 Client ===")
        self.host = host
        self.port = port
        self.device = WPA3Device(is_ap=False)
        self.ssid = "TestNetwork"
        self.password = "TestPassword123"
        print(f"\nClient - Using SSID: {self.ssid}")
        print(f"Client - Using password: {self.password}")
        self.device.derive_pmk(self.password, self.ssid)
        self.sta_mac = b'\x66\x77\x88\x99\xaa\xbb'
        print(f"Client - MAC Address: {binascii.hexlify(self.sta_mac).decode()}")
        
    def connect(self):
        print("\n=== Starting TCP Client ===")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"TCP Client - Initiating 3-way handshake with {self.host}:{self.port}")
            print("TCP Client - Sending SYN")
            client_socket.connect((self.host, self.port))
            print("TCP Client - Received SYN-ACK")
            print("TCP Client - Sent ACK")
            print("=== TCP 3-way Handshake Completed ===\n")
            
            print("Starting WPA3 4-way handshake...")
            
            # WPA3 Message 1
            print("\nWPA3 Message 1: Receiving ANonce")
            self.device.anonce = client_socket.recv(32)
            print("Client - ANonce received from AP")
            
            # WPA3 Message 2
            print("\nWPA3 Message 2: SNonce Generation and Exchange")
            self.device.snonce = self.device.generate_nonce()
            client_socket.send(self.device.snonce)
            client_socket.send(self.sta_mac)
            print("Client - SNonce and MAC address sent to AP")
            
            # WPA3 Message 3
            print("\nWPA3 Message 3: PTK Derivation and Receiving First Encrypted Message")
            ap_mac = b'\x00\x11\x22\x33\x44\x55'
            self.device.derive_ptk(
                self.device.anonce,
                self.device.snonce,
                ap_mac,
                self.sta_mac
            )
            encrypted = client_socket.recv(1024)
            decrypted = self.device.decrypt_message(encrypted)
            
            # WPA3 Message 4
            print("\nWPA3 Message 4: Sending Encrypted Response")
            response = "WPA3 Handshake acknowledged by client! Connection established successfully."
            print(f"Client - Sending encrypted response: {response}")
            encrypted_response = self.device.encrypt_message(response)
            client_socket.send(encrypted_response)
            print("=== WPA3 4-way Handshake Completed ===\n")
            
            # Additional message exchange
            print("\nStarting Post-Handshake Communication")
            for i in range(3):
                encrypted = client_socket.recv(1024)
                decrypted = self.device.decrypt_message(encrypted)
                
                response = f"Client Test Response #{i+1}: Message received and decrypted successfully!"
                print(f"\nClient - Sending response: {response}")
                encrypted_response = self.device.encrypt_message(response)
                client_socket.send(encrypted_response)
            
        except Exception as e:
            print(f"Client - Error during handshake: {e}")
        finally:
            client_socket.close()
            print("\nClient - Connection closed")

if __name__ == "__main__":
    import threading
    
    # Start server in a separate thread
    server = WPA3Server()
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Give server time to start
    import time
    time.sleep(1)
    
    # Start client
    client = WPA3Client()
    client.connect()