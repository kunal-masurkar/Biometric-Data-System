import os
import hashlib
import base64
import time
import getpass
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class User:
    def __init__(self, username, password_hash, role):
        self.username = username
        self.password_hash = password_hash
        self.role = role  # e.g., 'admin', 'user', 'manager'
        self.biometric_data = None
        self.authenticated = False

class AuthenticationModule:
    def __init__(self):
        self.users = {}
        self.load_users()
        
    def load_users(self):
        """Load users from storage or initialize with default admin"""
        try:
            with open('users.json', 'r') as f:
                user_data = json.load(f)
                for username, data in user_data.items():
                    self.users[username] = User(
                        username=username,
                        password_hash=data['password_hash'],
                        role=data['role']
                    )
        except FileNotFoundError:
            # Create default admin user if no users exist
            admin_pass = self.hash_password("admin123")
            self.users["admin"] = User("admin", admin_pass, "admin")
            self.save_users()
    
    def save_users(self):
        """Save users to storage"""
        user_data = {}
        for username, user in self.users.items():
            user_data[username] = {
                'password_hash': user.password_hash,
                'role': user.role
            }
        with open('users.json', 'w') as f:
            json.dump(user_data, f)
    
    def hash_password(self, password):
        """Hash a password for storage"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt.hex() + ':' + key.hex()
    
    def verify_password(self, stored_hash, provided_password):
        """Verify a stored password against a provided password"""
        salt, key = stored_hash.split(':')
        salt = bytes.fromhex(salt)
        key_to_check = hashlib.pbkdf2_hmac(
            'sha256', 
            provided_password.encode('utf-8'), 
            salt, 
            100000
        )
        return key_to_check.hex() == key
    
    def authenticate_user(self, username, password):
        """Authenticate a user with username and password (initial authentication)"""
        if username not in self.users:
            print("User not found")
            return None
        
        user = self.users[username]
        if not self.verify_password(user.password_hash, password):
            print("Incorrect password")
            return None
        
        user.authenticated = True
        print(f"User {username} authenticated successfully")
        return user
    
    def recaptcha_verification(self, user):
        """Simulate reCAPTCHA verification"""
        print("\n=== reCAPTCHA Verification ===")
        verification = input("Enter 'verify' to simulate passing reCAPTCHA: ")
        if verification.lower() == 'verify':
            print("reCAPTCHA verification successful")
            return True
        print("reCAPTCHA verification failed")
        user.authenticated = False
        return False
    
    def register_new_user(self, username, password, role='user'):
        """Register a new user"""
        if username in self.users:
            print(f"User {username} already exists")
            return False
        
        password_hash = self.hash_password(password)
        self.users[username] = User(username, password_hash, role)
        self.save_users()
        print(f"User {username} registered successfully")
        return True

class BiometricInterface:
    def __init__(self):
        pass
    
    def collect_biometric_data(self):
        """Simulates collecting biometric data from a user"""
        print("\n=== Biometric Data Collection ===")
        print("Please provide your biometric data:")
        fingerprint = input("Fingerprint scan (simulate with text): ")
        face_scan = input("Face scan (simulate with text): ")
        
        # In a real system, we'd process actual biometric inputs
        biometric_data = {
            'fingerprint': fingerprint,
            'face_scan': face_scan,
            'timestamp': time.time()
        }
        return biometric_data

class EncryptionModule:
    def __init__(self):
        # Generate a secure key (for demo purposes - in production, use a key management system)
        self.key = os.urandom(32)  # 256-bit key for AES-256
    
    def validate_and_preprocess(self, biometric_data):
        """Validate and preprocess biometric data before encryption"""
        if not biometric_data:
            return None
        
        # Add metadata for validation
        biometric_data['validated'] = True
        biometric_data['processed_timestamp'] = time.time()
        return biometric_data
    
    def encrypt_data(self, data):
        """Encrypt data using AES-256"""
        # Convert data to JSON string and then to bytes
        data_bytes = json.dumps(data).encode('utf-8')
        
        # Pad the data to match the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()
        
        # Generate initialization vector
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV and encrypted data for storage
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')
        }
    
    def decrypt_data(self, encrypted_package):
        """Decrypt data using AES-256"""
        # Extract IV and encrypted data
        iv = base64.b64decode(encrypted_package['iv'])
        encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data_bytes = unpadder.update(padded_data) + unpadder.finalize()
        
        # Convert back to dictionary
        return json.loads(data_bytes.decode('utf-8'))

class StorageModule:
    def __init__(self):
        self.storage_path = 'secure_storage'
        os.makedirs(self.storage_path, exist_ok=True)
    
    def store_biometric_data(self, username, encrypted_data):
        """Store encrypted biometric data"""
        file_path = os.path.join(self.storage_path, f"{username}_biometric.enc")
        with open(file_path, 'w') as f:
            json.dump(encrypted_data, f)
        print(f"Encrypted biometric data stored for {username}")
        return True
    
    def retrieve_encrypted_data(self, username):
        """Retrieve encrypted biometric data"""
        file_path = os.path.join(self.storage_path, f"{username}_biometric.enc")
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"No biometric data found for {username}")
            return None

class AccessControlModule:
    def __init__(self, authentication_module, encryption_module, storage_module):
        self.authentication = authentication_module
        self.encryption = encryption_module
        self.storage = storage_module
        self.permissions = {
            'admin': ['read', 'write', 'delete', 'manage_users'],
            'manager': ['read', 'write'],
            'user': ['read']
        }
    
    def check_authorization(self, user, action):
        """Check if user is authorized for a particular action"""
        if not user or not user.authenticated:
            print("User not authenticated")
            return False
        
        if user.role not in self.permissions:
            print(f"Unknown role: {user.role}")
            return False
        
        if action not in self.permissions[user.role]:
            print(f"User {user.username} doesn't have permission for {action}")
            return False
        
        return True
    
    def verify_authentication(self, user):
        """Verify that user is authenticated"""
        return user and user.authenticated
    
    def retrieve_biometric_data(self, user, target_username):
        """Retrieve and decrypt biometric data"""
        # Check if user is authorized to read biometric data
        if not self.check_authorization(user, 'read'):
            return None
        
        # Retrieve encrypted data
        encrypted_data = self.storage.retrieve_encrypted_data(target_username)
        if not encrypted_data:
            return None
        
        # Decrypt the data
        decrypted_data = self.encryption.decrypt_data(encrypted_data)
        print(f"Successfully retrieved biometric data for {target_username}")
        return decrypted_data
    
    def store_new_biometric_data(self, user, target_username, biometric_data):
        """Process and store new biometric data"""
        # Check if user is authorized to write biometric data
        if not self.check_authorization(user, 'write'):
            return False
        
        # Validate and preprocess the data
        processed_data = self.encryption.validate_and_preprocess(biometric_data)
        if not processed_data:
            print("Invalid biometric data")
            return False
        
        # Encrypt the data
        encrypted_data = self.encryption.encrypt_data(processed_data)
        
        # Store the encrypted data
        success = self.storage.store_biometric_data(target_username, encrypted_data)
        return success

class BiometricSystem:
    def __init__(self):
        self.authentication = AuthenticationModule()
        self.encryption = EncryptionModule()
        self.storage = StorageModule()
        self.access_control = AccessControlModule(
            self.authentication, 
            self.encryption, 
            self.storage
        )
        self.biometric_interface = BiometricInterface()
        self.current_user = None
    
    def login(self):
        """User login process"""
        print("\n=== Login ===")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        # Initial authentication
        user = self.authentication.authenticate_user(username, password)
        if not user:
            return False
        
        # reCAPTCHA verification
        if not self.authentication.recaptcha_verification(user):
            return False
        
        self.current_user = user
        return True
    
    def register(self):
        """Register a new user"""
        print("\n=== User Registration ===")
        username = input("New username: ")
        password = getpass.getpass("New password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match")
            return False
        
        role = 'user'  # Default role
        if self.current_user and self.current_user.role == 'admin':
            role = input("Role (admin/manager/user): ").lower()
            if role not in ['admin', 'manager', 'user']:
                print("Invalid role, setting to 'user'")
                role = 'user'
        
        success = self.authentication.register_new_user(username, password, role)
        if success:
            return self.collect_and_store_biometric(username)
        return False
    
    def collect_and_store_biometric(self, username):
        """Collect and store biometric data for a user"""
        print(f"\nCollecting biometric data for {username}")
        biometric_data = self.biometric_interface.collect_biometric_data()
        
        success = self.access_control.store_new_biometric_data(
            self.current_user,
            username,
            biometric_data
        )
        
        if success:
            print(f"Biometric data processed and stored for {username}")
        else:
            print(f"Failed to process biometric data for {username}")
        
        return success
    
    def view_biometric_data(self):
        """View biometric data for a user"""
        if not self.current_user:
            print("You must be logged in")
            return
        
        print("\n=== View Biometric Data ===")
        username = input("Enter username to view data: ")
        
        decrypted_data = self.access_control.retrieve_biometric_data(
            self.current_user,
            username
        )
        
        if decrypted_data:
            print("\nBiometric Data:")
            for key, value in decrypted_data.items():
                print(f"{key}: {value}")
        else:
            print("Failed to retrieve biometric data")
    
    def run(self):
        """Run the biometric system interface"""
        print("Welcome to the Biometric Data System")
        
        while True:
            print("\n=== Main Menu ===")
            if not self.current_user:
                print("1. Login")
                print("2. Exit")
                choice = input("Enter choice: ")
                
                if choice == '1':
                    self.login()
                elif choice == '2':
                    print("Exiting system...")
                    break
                else:
                    print("Invalid choice")
            else:
                print(f"Logged in as: {self.current_user.username} ({self.current_user.role})")
                print("1. Register new user")
                print("2. View biometric data")
                print("3. Update my biometric data")
                print("4. Logout")
                print("5. Exit")
                choice = input("Enter choice: ")
                
                if choice == '1':
                    self.register()
                elif choice == '2':
                    self.view_biometric_data()
                elif choice == '3':
                    self.collect_and_store_biometric(self.current_user.username)
                elif choice == '4':
                    print(f"Logging out {self.current_user.username}")
                    self.current_user = None
                elif choice == '5':
                    print("Exiting system...")
                    break
                else:
                    print("Invalid choice")

# Run the system
if __name__ == "__main__":
    system = BiometricSystem()
    system.run()
