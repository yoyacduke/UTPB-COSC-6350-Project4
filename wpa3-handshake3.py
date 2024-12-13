import socket
import secrets
import hashlib
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

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
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"\nAP - Listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = server_socket.accept()
            print(f"\nAP - New connection from {addr}")
            self.handle_client(client_socket)
            
    def handle_client(self, client_socket):
        try:
            print("\n=== Starting WPA3 Handshake (AP Side) ===")
            
            # Step 1: Generate and send ANonce
            print("\nStep 1: ANonce Generation and Exchange")
            self.device.anonce = self.device.generate_nonce()
            client_socket.send(self.device.anonce)
            print("AP - ANonce sent to client")
            
            # Step 2: Receive SNonce
            print("\nStep 2: SNonce Reception")
            self.device.snonce = client_socket.recv(32)
            print("AP - Received SNonce from client")
            
            # Step 3: PTK Derivation
            print("\nStep 3: PTK Derivation")
            sta_mac = client_socket.recv(6)
            print(f"AP - Client MAC received: {binascii.hexlify(sta_mac).decode()}")
            self.device.derive_ptk(
                self.device.anonce,
                self.device.snonce,
                self.ap_mac,
                sta_mac
            )
            
            # Step 4: Test Encrypted Communication
            print("\nStep 4: Testing Encrypted Communication")
            test_message = "WPA3 Handshake completed successfully! This is a test message from the AP."
            print(f"AP - Sending encrypted message: {test_message}")
            encrypted = self.device.encrypt_message(test_message)
            client_socket.send(encrypted)
            
            # Step 5: Receive Client's Response
            print("\nStep 5: Receiving Client's Response")
            encrypted_response = client_socket.recv(1024)
            decrypted = self.device.decrypt_message(encrypted_response)
            
            # Step 6: Additional Message Exchange
            print("\nStep 6: Additional Message Exchange")
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
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"\nClient - Connecting to {self.host}:{self.port}")
            client_socket.connect((self.host, self.port))
            print("\n=== Starting WPA3 Handshake (Client Side) ===")
            
            # Step 1: Receive ANonce
            print("\nStep 1: ANonce Reception")
            self.device.anonce = client_socket.recv(32)
            print("Client - ANonce received from AP")
            
            # Step 2: Generate and send SNonce
            print("\nStep 2: SNonce Generation and Exchange")
            self.device.snonce = self.device.generate_nonce()
            client_socket.send(self.device.snonce)
            print("Client - SNonce sent to AP")
            
            # Step 3: Send MAC and derive PTK
            print("\nStep 3: PTK Derivation")
            client_socket.send(self.sta_mac)
            print("Client - MAC address sent to AP")
            
            ap_mac = b'\x00\x11\x22\x33\x44\x55'
            self.device.derive_ptk(
                self.device.anonce,
                self.device.snonce,
                ap_mac,
                self.sta_mac
            )
            
            # Step 4: Receive and Process Encrypted Message
            print("\nStep 4: Processing Encrypted Communication")
            encrypted = client_socket.recv(1024)
            decrypted = self.device.decrypt_message(encrypted)
            
            # Step 5: Send Response
            print("\nStep 5: Sending Response")
            response = "WPA3 Handshake acknowledged by client! Connection established successfully."
            print(f"Client - Sending encrypted response: {response}")
            encrypted_response = self.device.encrypt_message(response)
            client_socket.send(encrypted_response)
            
            # Step 6: Additional Message Exchange
            print("\nStep 6: Additional Message Exchange")
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
