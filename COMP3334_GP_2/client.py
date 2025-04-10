import os
import json
import hashlib
import base64
import time
import getpass
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import random
import string
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Union

# Client constant, exists only on client side
CLIENT_CONSTANT = "S3cureF1leSystem"

# Blacklisted passwords
BLACKLISTED_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "admin", "welcome",
    "1234", "abc123", "password1", "changeme", "letmein", "welcome1",
    "monkey", "sunshine", "superman"
]

class FileClient:
    def __init__(self, server_dir: str = "server"):
        self.server_dir = Path(server_dir)
        self.server = None  # In a real application, this would be a network connection
        
        # Current user state
        self.username = None
        self.sub_master_key = None
        self.private_key = None
        self.public_key = None
    
    def evaluate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Evaluate password strength according to NIST guidelines"""
        # Check password length
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        # Check if in blacklist
        if password.lower() in BLACKLISTED_PASSWORDS:
            return False, "This password is too common. Please choose a stronger one"
        
        # Evaluate strength based on length
        strength = "Weak"
        if len(password) >= 12:
            strength = "Strong"
        elif len(password) >= 10:
            strength = "Medium"
        
        return True, strength
    
    def generate_master_key(self, password: str) -> bytes:
        """Generate master key from password"""
        # Use password and client constant to generate master key
        key_material = password + CLIENT_CONSTANT
        return hashlib.sha256(key_material.encode()).digest()
    
    def generate_file_key(self, sub_master_key: bytes, filename: str) -> bytes:
        """Generate file key from sub-master key and filename"""
        key_material = sub_master_key + filename.encode()
        return hashlib.sha256(key_material).digest()
    
    def encrypt_data(self, data: Union[str, bytes], key: bytes) -> str:
        """Encrypt data using AES"""
        if isinstance(data, str):
            data = data.encode()
        
        # Create initialization vector
        iv = os.urandom(16)
        
        # Create padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        result = base64.b64encode(iv + encrypted_data).decode()
        return result
    
    def decrypt_data(self, encrypted_data: str, key: bytes) -> bytes:
        """Decrypt data using AES"""
        # Decode base64
        raw_data = base64.b64decode(encrypted_data)
        
        # Extract IV and encrypted data
        iv = raw_data[:16]
        ciphertext = raw_data[16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    def generate_keypair(self) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def sign_data(self, data: str) -> str:
        """Sign data using private key"""
        if not self.private_key:
            raise ValueError("Private key not available")
        
        signature = self.private_key.sign(
            data.encode(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def get_timestamp(self) -> str:
        """Get current timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def register(self, is_admin=False) -> None:
        """User registration"""
        print("\n=== User Registration ===")
        if is_admin:
            print("Registering as ADMINISTRATOR")
        
        username = input("Enter username: ").strip()
        
        # Check if username is empty
        if not username:
            print("Username cannot be empty")
            return
        
        # Input password and confirmation
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match")
            return
        
        # Evaluate password strength
        valid, strength = self.evaluate_password_strength(password)
        if not valid:
            print(f"Password not strong enough: {strength}")
            return
        
        print(f"Password strength: {strength}")
        
        # Generate keys
        master_key = self.generate_master_key(password)
        sub_master_key = os.urandom(32)  # Randomly generate sub-master key
        
        # Generate key pair
        private_key, public_key = self.generate_keypair()
        
        # Serialize keys
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Encrypt keys
        encrypted_sub_master_key = self.encrypt_data(sub_master_key, master_key)
        encrypted_private_key = self.encrypt_data(private_key_pem, master_key)
        
        # Get server salt
        success, server_salt = self.get_salt_from_server(username)
        
        if not success:
            # If user doesn't exist, server will return a new salt
            server_salt = "NEW_USER_SALT"
        
        # Calculate password hash
        password_hash = hashlib.sha256((password + server_salt).encode()).hexdigest()
        
        success, message = self.send_registration_to_server(
            username, password, encrypted_sub_master_key, 
            encrypted_private_key, public_key_pem, is_admin
        )
        
        print(message)
    
    def login(self) -> bool:
        """User login"""
        print("\n=== User Login ===")
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        
        # Get server salt
        success, server_salt = self.get_salt_from_server(username)
        if not success:
            print("Invalid username or password")
            return False
        
        # Calculate password hash
        password_hash = hashlib.sha256((password + server_salt).encode()).hexdigest()
        
        # First stage login: password verification
        success, otp = self.send_login_to_server(username, password_hash)
        if not success:
            print("Invalid username or password")
            return False
        
        # Display OTP window
        self.show_otp_window(otp)
        
        # Input OTP
        entered_otp = input("Enter the OTP code shown in the popup: ")
        
        # Second stage login: OTP verification
        success, user_keys = self.send_otp_to_server(username, entered_otp)
        if not success:
            print("Invalid OTP or OTP expired")
            return False
        
        # Use master key to decrypt sub-master key and private key
        master_key = self.generate_master_key(password)
        
        try:
            # Decrypt Sub Master Key
            decrypted_sub_master_key = self.decrypt_data(
                user_keys["encrypted_sub_master_key"], master_key
            )
            
            # Decrypt private key
            decrypted_private_key_pem = self.decrypt_data(
                user_keys["encrypted_private_key"], master_key
            ).decode()
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                decrypted_private_key_pem.encode(),
                password=None
            )
            
            # Load public key
            public_key_pem = user_keys["public_key"]
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
            
            # Save login state
            self.username = username
            self.sub_master_key = decrypted_sub_master_key
            self.private_key = private_key
            self.public_key = public_key
            
            print(f"Welcome, {username}!")
            return True
            
        except Exception as e:
            print(f"Error decrypting keys: {e}")
            return False
    
    def show_otp_window(self, otp: str) -> None:
        """Display OTP window (non-blocking)"""
        
        def show_window():
            root = tk.Tk()
            root.title("Two-Factor Authentication")
            root.geometry("300x150")
            
            frame = tk.Frame(root, padx=20, pady=20)
            frame.pack(fill=tk.BOTH, expand=True)
            
            tk.Label(frame, text="Your One-Time Password:", font=("Arial", 12)).pack()
            tk.Label(frame, text=otp, font=("Arial", 18, "bold")).pack(pady=10)
            tk.Label(frame, text="This code will expire in 30 seconds", font=("Arial", 10)).pack()
            
            # Auto-close window after 30 seconds
            root.after(30000, root.destroy)
            root.mainloop()
        
        # Run window in a new thread
        otp_thread = threading.Thread(target=show_window)
        otp_thread.daemon = True  # Set as daemon thread so it terminates when main program exits
        otp_thread.start()
        
        # Main thread continues running
        print("OTP window displayed. You can enter the code below when ready.")
    
    def upload_file(self) -> None:
        """Upload file"""
        if not self.username:
            print("Please login first")
            return
        
        print("\n=== Upload File ===")
        file_path = input("Enter file path: ").strip()
        
        # Check if file exists
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            return
        
        filename = os.path.basename(file_path)
        
        # Read file
        try:
            with open(file_path, "rb") as f:
                file_content = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return
        
        # Generate file key
        file_key = self.generate_file_key(self.sub_master_key, filename)
        
        # Encrypt file
        encrypted_content = self.encrypt_data(file_content, file_key)
        
        # Encrypt file key using sub-master key
        encrypted_file_key = self.encrypt_data(file_key, self.sub_master_key)
        
        # Get current timestamp
        timestamp = self.get_timestamp()
        
        # Calculate data hash
        content_hash = hashlib.sha256(encrypted_content.encode()).hexdigest()
        
        # Create signature data
        signature_data = f"{self.username}{timestamp}UPLOAD{content_hash}"
        
        # Sign
        signature = self.sign_data(signature_data)
        
        # Send upload request to server
        success, message = self.upload_file_to_server(
            filename, encrypted_content, encrypted_file_key, signature, timestamp
        )
        
        print(message)

    def decrypt_with_private_key(self, encrypted_data: str) -> bytes:
        """Decrypt data using the user's private key"""
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Decrypt using private key
            decrypted_data = self.private_key.decrypt(
                encrypted_bytes,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted_data
        except Exception as e:
            raise ValueError(f"Failed to decrypt shared file key: {e}")
    
    def download_file(self) -> None:
        """Download file"""
        if not self.username:
            print("Please login first")
            return
        
        print("\n=== Download File ===")
        
        # Get file list
        own_files, shared_files = self.list_files()
        
        if not own_files and not shared_files:
            print("No files available")
            return
        
        print("Available files:")
        all_files = []
        is_shared_file = []  # Keep track of whether each file is shared
        
        if own_files:
            print("\nYour files:")
            for i, file in enumerate(own_files):
                print(f"{i+1}. {file}")
                all_files.append(file)
                is_shared_file.append(False)  # Own files
        
        if shared_files:
            print("\nShared with you:")
            for i, file in enumerate(shared_files, start=len(own_files)+1):
                print(f"{i}. {file}")
                all_files.append(file)
                is_shared_file.append(True)  # Shared files
        
        try:
            choice_str = input("\nEnter the number of the file to download (0 to cancel): ").strip()
            
            # Validate input is a number
            if not choice_str.isdigit():
                print("Please enter a valid number")
                return
            
            choice = int(choice_str)
            
            if choice == 0:
                return
            
            if choice < 1 or choice > len(all_files):
                print("Invalid selection number")
                return
            
            # Get selected filename
            filename = all_files[choice-1]
            shared = is_shared_file[choice-1]  # Check if it's a shared file
            
            # Get current timestamp
            timestamp = self.get_timestamp()
            
            # Create signature data
            signature_data = f"{self.username}{timestamp}DOWNLOAD{filename}"
            
            # Sign
            signature = self.sign_data(signature_data)
            
            # Send download request to server
            success, encrypted_content, encrypted_key = self.download_file_from_server(
                filename, signature, timestamp
            )
            
            if not success:
                print("Failed to download file")
                return
            
            # Decrypt file key - Different method based on whether it's a shared file
            if shared:
                # For shared files, decrypt with private key
                file_key = self.decrypt_with_private_key(encrypted_key)
            else:
                # For own files, decrypt with sub-master key
                file_key = self.decrypt_data(encrypted_key, self.sub_master_key)
            
            # Decrypt file content
            decrypted_content = self.decrypt_data(encrypted_content, file_key)
            
            # Ask for save path
            save_path = input("Enter path to save the file (or press Enter for current directory): ").strip()
            if not save_path:
                save_path = os.getcwd()
            
            # Ensure save path exists
            if not os.path.isdir(save_path):
                print(f"Directory not found: {save_path}")
                return
            
            # Extract original filename for shared files (remove "from_username_" prefix)
            if shared and filename.startswith("from_"):
                save_filename = filename.split("_", 2)[2]  # Get part after "from_username_"
            else:
                save_filename = filename
            
            # Construct full save path
            full_save_path = os.path.join(save_path, save_filename)
            
            # Save file
            with open(full_save_path, "wb") as f:
                f.write(decrypted_content)
            
            print(f"File saved to {full_save_path}")
            
        except Exception as e:
            print(f"Input error: {e}")
    
    def delete_file(self) -> None:
        """Delete file"""
        if not self.username:
            print("Please login first")
            return
        
        print("\n=== Delete File ===")
        
        # Get only user's own files
        own_files, _ = self.list_files()
        
        if not own_files:
            print("You don't have any files to delete")
            return
        
        print("Your files:")
        for i, file in enumerate(own_files):
            print(f"{i+1}. {file}")
        
        try:
            choice = int(input("\nEnter the number of the file to delete (0 to cancel): "))
            if choice == 0:
                return
            
            # Get selected filename
            filename = own_files[choice-1]
            
            # Confirm deletion
            confirm = input(f"Are you sure you want to delete '{filename}'? (y/N): ").strip().lower()
            if confirm != 'y':
                print("Delete cancelled")
                return
            
            # Get current timestamp
            timestamp = self.get_timestamp()
            
            # Create signature data
            signature_data = f"{self.username}{timestamp}DELETE{filename}"
            
            # Sign
            signature = self.sign_data(signature_data)
            
            # Send delete request to server
            success, message = self.delete_file_from_server(
                filename, signature, timestamp
            )
            
            print(message)
            
        except ValueError:
            print("Please enter a valid number")
        except IndexError:
            print("Invalid selection")
    
    def share_file(self) -> None:
        """Share file"""
        if not self.username:
            print("Please login first")
            return
        
        print("\n=== Share File ===")
        
        # Get only user's own files
        own_files, _ = self.list_files()
        
        if not own_files:
            print("You don't have any files to share")
            return
        
        print("Your files:")
        for i, file in enumerate(own_files):
            print(f"{i+1}. {file}")
        
        try:
            choice = int(input("\nEnter the number of the file to share (0 to cancel): "))
            if choice == 0:
                return
            
            # Get selected filename
            filename = own_files[choice-1]
            
            # Input target user
            target_username = input("Enter username to share with: ").strip()
            
            if not target_username or target_username == self.username:
                print("Invalid target username")
                return
            
            # Get target user's public key
            target_public_key = self.get_user_public_key(target_username)
            
            if not target_public_key:
                print(f"User {target_username} not found")
                return
            
            # Generate file key
            file_key = self.generate_file_key(self.sub_master_key, filename)
            
            # Encrypt file key using target user's public key
            encrypted_key_for_target = self.encrypt_with_public_key(
                file_key, target_public_key
            )
            
            # Get current timestamp
            timestamp = self.get_timestamp()
            
            # Create signature data
            signature_data = f"{self.username}{timestamp}SHARE{filename}{target_username}"
            
            # Sign
            signature = self.sign_data(signature_data)
            
            # Send share request to server
            success, message = self.share_file_with_server(
                filename, target_username, encrypted_key_for_target, 
                signature, timestamp
            )
            
            print(message)
            
        except ValueError:
            print("Please enter a valid number")
        except IndexError:
            print("Invalid selection")
    
    def encrypt_with_public_key(self, data: bytes, public_key_pem: str) -> str:
        """Encrypt data using public key"""
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode()
        )
        
        # Encrypt using public key
        encrypted_data = public_key.encrypt(
            data,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted_data).decode()
    
    def list_files(self) -> Tuple[List[str], List[str]]:
        """List user's files"""
        if not self.username:
            print("Please login first")
            return [], []
        
        # Get current timestamp
        timestamp = self.get_timestamp()
        
        # Create signature data
        signature_data = f"{self.username}{timestamp}LIST"
        
        # Sign
        signature = self.sign_data(signature_data)
        
        # Request file list from server
        success, own_files, shared_files = self.list_files_from_server(
            signature, timestamp
        )
        
        if not success:
            return [], []
        
        return own_files, shared_files
    
    def view_logs(self) -> None:
        """View system logs (admin only)"""
        if not self.username:
            print("Please login first")
            return
        
        # Get current timestamp
        timestamp = self.get_timestamp()
        
        # Create signature data
        signature_data = f"{self.username}{timestamp}VIEWLOGS"
        
        # Sign
        signature = self.sign_data(signature_data)
        
        # Request logs from server
        success, logs = self.view_logs_from_server(signature, timestamp)
        
        if success:
            print("\n=== System Logs ===\n")
            print(logs)
        else:
            print("You don't have permission to view logs")
    
    # ========== Server communication simulation functions ==========
    # In a real application, these would be network API calls
    
    def get_salt_from_server(self, username: str) -> Tuple[bool, str]:
        """Get salt from server"""
        # Check if user exists
        users_file = self.server_dir / "users.json"
        if not users_file.exists():
            return False, "User not found"
        
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            # For new users, return a new salt
            return False, "NEW_USER_SALT"
        
        return True, users[username]["server_salt"]
    
    def send_registration_to_server(self, username: str, password: str, 
                            encrypted_sub_master_key: str, encrypted_private_key: str, 
                            public_key: str, is_admin: bool = False) -> Tuple[bool, str]:
        """Send registration request to server"""
        # Ensure server directory exists
        self.server_dir.mkdir(exist_ok=True)
        
        # Check if username already exists
        users_file = self.server_dir / "users.json"
        if users_file.exists():
            with open(users_file, "r") as f:
                users = json.load(f)
            
            if username in users:
                return False, "Username already exists"
        else:
            # If users.json doesn't exist, create an empty dictionary
            users = {}
        
        # If registering as admin but admin already exists, verify
        if is_admin:
            admin_exists = any(user.get("is_admin", False) for user in users.values())
            if admin_exists:
                admin_password = getpass.getpass("Admin already exists. Enter current admin password: ")
        
        # Generate server salt
        server_salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # Calculate password hash using the new salt
        password_hash = hashlib.sha256((password + server_salt).encode()).hexdigest()
        
        # Store user data
        users[username] = {
            "password_hash": password_hash,  # Hash calculated with the new salt
            "server_salt": server_salt,
            "public_key": public_key,
            "is_admin": is_admin
        }
        
        with open(users_file, "w") as f:
            json.dump(users, f)
        
        # Create user directory structure
        user_dir = self.server_dir / username
        user_dir.mkdir(exist_ok=True)
        
        # Create keys directory
        keys_dir = user_dir / "keys"
        keys_dir.mkdir(exist_ok=True)
        
        # Save encrypted keys
        with open(keys_dir / "sub_master_key.enc", "w") as f:
            f.write(encrypted_sub_master_key)
        
        with open(keys_dir / "private_key.enc", "w") as f:
            f.write(encrypted_private_key)
        
        with open(keys_dir / "public_key", "w") as f:
            f.write(public_key)
        
        # Create file directories
        (user_dir / "own_files").mkdir(exist_ok=True)
        (user_dir / "shared_files").mkdir(exist_ok=True)
        
        # Log action
        if is_admin:
            self.log_action("SYSTEM", "REGISTER", f"Admin {username} registered")
        else:
            self.log_action("SYSTEM", "REGISTER", f"User {username} registered")
        
        return True, f"{'Admin' if is_admin else 'User'} registered successfully"
    
    def send_login_to_server(self, username: str, password_hash: str) -> Tuple[bool, str]:
        """Send login request to server"""
        # Simulate server login function
        users_file = self.server_dir / "users.json"
        if not users_file.exists():
            return False, ""
        
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            return False, ""
        
        if users[username]["password_hash"] != password_hash:
            self.log_action(username, "LOGIN_FAILED", "Invalid password")
            return False, ""
        
        # Generate OTP code
        import random
        import string
        otp = ''.join(random.choices(string.digits, k=6))
        expiry_time = time.time() + 60  # Expire after 60 seconds
        
        # Store OTP and expiry time in temporary file
        otp_data = {"otp": otp, "expiry_time": expiry_time}
        otp_file = self.server_dir / f"otp_{username}.json"
        with open(otp_file, "w") as f:
            json.dump(otp_data, f)
        
        # Log action
        self.log_action(username, "LOGIN_STAGE1", "Password verification successful, OTP generated")
        
        return True, otp
    
    def send_otp_to_server(self, username: str, otp: str) -> Tuple[bool, Dict]:
        """Send OTP verification request to server"""
        # Read OTP data from file
        otp_file = self.server_dir / f"otp_{username}.json"
        if not otp_file.exists():
            return False, {}
        
        with open(otp_file, "r") as f:
            otp_data = json.load(f)
        
        # Delete OTP file regardless of verification success
        otp_file.unlink()
        
        # Check if OTP is expired
        if time.time() > otp_data["expiry_time"]:
            self.log_action(username, "LOGIN_FAILED", "OTP expired")
            return False, {}
        
        # Check if OTP is correct
        if otp != otp_data["otp"]:
            self.log_action(username, "LOGIN_FAILED", "Invalid OTP")
            return False, {}
        
        # Get user's encrypted keys
        user_dir = self.server_dir / username
        keys_dir = user_dir / "keys"
        
        if not keys_dir.exists():
            return False, {}
        
        user_keys = {}
        
        try:
            with open(keys_dir / "sub_master_key.enc", "r") as f:
                user_keys["encrypted_sub_master_key"] = f.read()
            
            with open(keys_dir / "private_key.enc", "r") as f:
                user_keys["encrypted_private_key"] = f.read()
            
            with open(keys_dir / "public_key", "r") as f:
                user_keys["public_key"] = f.read()
            
            # Log action
            self.log_action(username, "LOGIN_SUCCESS", "OTP verification successful")
            
            return True, user_keys
            
        except Exception as e:
            print(f"Error reading keys: {e}")
            return False, {}
    
    def upload_file_to_server(self, filename: str, encrypted_content: str, 
                             encrypted_key: str, signature: str, timestamp: str) -> Tuple[bool, str]:
        """Upload file to server"""
        # Verify signature
        verification_data = f"{self.username}{timestamp}UPLOAD{hashlib.sha256(encrypted_content.encode()).hexdigest()}"
        if not self.verify_signature(self.username, verification_data, signature):
            self.log_action(self.username, "UPLOAD_FAILED", f"Invalid signature for file: {filename}")
            return False, "Invalid signature"
        
        # Save file and key
        user_files_dir = self.server_dir / self.username / "own_files"
        file_path = user_files_dir / filename
        key_path = user_files_dir / f"{filename}.key"
        
        with open(file_path, "w") as f:
            f.write(encrypted_content)
        
        with open(key_path, "w") as f:
            f.write(encrypted_key)
        
        self.log_action(self.username, "UPLOAD", f"File uploaded: {filename}")
        return True, "File uploaded successfully"
    
    def download_file_from_server(self, filename: str, signature: str, 
                                timestamp: str) -> Tuple[bool, str, str]:
        """Download file from server"""
        # Verify signature
        verification_data = f"{self.username}{timestamp}DOWNLOAD{filename}"
        if not self.verify_signature(self.username, verification_data, signature):
            self.log_action(self.username, "DOWNLOAD_FAILED", f"Invalid signature for file: {filename}")
            return False, "", ""
        
        # Check if it's user's own file or a shared file
        own_file_path = self.server_dir / self.username / "own_files" / filename
        own_key_path = self.server_dir / self.username / "own_files" / f"{filename}.key"
        
        shared_file_path = self.server_dir / self.username / "shared_files" / filename
        shared_key_path = self.server_dir / self.username / "shared_files" / f"{filename}.key"
        
        file_path = None
        key_path = None
        
        if own_file_path.exists() and own_key_path.exists():
            file_path = own_file_path
            key_path = own_key_path
        elif shared_file_path.exists() and shared_key_path.exists():
            # If it's a shared file (which might be a symlink), resolve it
            if shared_file_path.is_symlink():
                # Get the target of the symlink
                target_path = shared_file_path.resolve()
                # Check if the target file still exists
                if not target_path.exists():
                    self.log_action(self.username, "DOWNLOAD_FAILED", f"Shared file no longer exists: {filename}")
                    return False, "", ""
            file_path = shared_file_path
            key_path = shared_key_path
        else:
            self.log_action(self.username, "DOWNLOAD_FAILED", f"File not found: {filename}")
            return False, "", ""
        
        # Read file and key
        try:
            with open(file_path, "r") as f:
                file_content = f.read()
            
            with open(key_path, "r") as f:
                encrypted_key = f.read()
            
            self.log_action(self.username, "DOWNLOAD", f"File downloaded: {filename}")
            return True, file_content, encrypted_key
        except FileNotFoundError:
            self.log_action(self.username, "DOWNLOAD_FAILED", f"File or key not accessible: {filename}")
            return False, "", ""
    
    def delete_file_from_server(self, filename: str, signature: str, 
                            timestamp: str) -> Tuple[bool, str]:
        """Delete file from server and remove all related shared copies"""
        # Verify signature
        verification_data = f"{self.username}{timestamp}DELETE{filename}"
        if not self.verify_signature(self.username, verification_data, signature):
            self.log_action(self.username, "DELETE_FAILED", f"Invalid signature for file: {filename}")
            return False, "Invalid signature"
        
        # Check if file exists
        file_path = self.server_dir / self.username / "own_files" / filename
        key_path = self.server_dir / self.username / "own_files" / f"{filename}.key"
        
        if not file_path.exists() or not key_path.exists():
            self.log_action(self.username, "DELETE_FAILED", f"File not found: {filename}")
            return False, "File not found"
        
        # Check sharing registry for any copies of this file
        sharing_registry_path = self.server_dir / "sharing_registry.json"
        shared_files_to_remove = []
        
        if sharing_registry_path.exists():
            try:
                with open(sharing_registry_path, "r") as f:
                    sharing_registry = json.load(f)
                    
                # Get the key for this file
                file_key = str(file_path)
                
                # Find all shared copies of this file
                if file_key in sharing_registry:
                    shared_files_to_remove = sharing_registry[file_key]
                    # Remove this file from registry
                    del sharing_registry[file_key]
                    
                    # Update registry
                    with open(sharing_registry_path, "w") as f:
                        json.dump(sharing_registry, f)
            except Exception as e:
                self.log_action(self.username, "DELETE_REGISTRY_ERROR", 
                            f"Error accessing sharing registry: {e}")
        
        # Delete all shared copies
        for shared_info in shared_files_to_remove:
            try:
                # Get paths
                target_file_path = Path(shared_info["target_file"])
                target_key_path = Path(shared_info["target_key"])
                target_meta_path = Path(shared_info["target_meta"])
                target_user = shared_info["target_user"]
                
                # Delete files
                if target_file_path.exists():
                    target_file_path.unlink()
                if target_key_path.exists():
                    target_key_path.unlink()
                if target_meta_path.exists():
                    target_meta_path.unlink()
                    
                self.log_action(self.username, "DELETE_SHARED", 
                            f"Removed shared copy from user {target_user}")
            except Exception as e:
                self.log_action(self.username, "DELETE_SHARED_FAILED", 
                            f"Failed to remove shared copy: {e}")
        
        # Delete original file
        try:
            file_path.unlink()
            key_path.unlink()
            
            # Log deletion
            num_shared = len(shared_files_to_remove)
            if num_shared > 0:
                self.log_action(self.username, "DELETE", f"File deleted: {filename} (and {num_shared} shared copies)")
            else:
                self.log_action(self.username, "DELETE", f"File deleted: {filename}")
                
            return True, f"File deleted successfully" + (f" (including {num_shared} shared copies)" if num_shared > 0 else "")
        except Exception as e:
            self.log_action(self.username, "DELETE_FAILED", f"Error deleting file {filename}: {e}")
            return False, f"Error deleting file: {e}"
    
    def share_file_with_server(self, filename: str, target_username: str, 
                            encrypted_key: str, signature: str, timestamp: str) -> Tuple[bool, str]:
        """Request file sharing from server with file copy instead of symlinks"""
        # Verify signature
        verification_data = f"{self.username}{timestamp}SHARE{filename}{target_username}"
        if not self.verify_signature(self.username, verification_data, signature):
            self.log_action(self.username, "SHARE_FAILED", f"Invalid signature for sharing file: {filename}")
            return False, "Invalid signature"
        
        # Check if file exists
        src_file_path = self.server_dir / self.username / "own_files" / filename
        src_key_path = self.server_dir / self.username / "own_files" / f"{filename}.key"
        if not src_file_path.exists() or not src_key_path.exists():
            self.log_action(self.username, "SHARE_FAILED", f"File not found: {filename}")
            return False, "File not found"
        
        # Check if target user exists
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if target_username not in users:
            self.log_action(self.username, "SHARE_FAILED", f"Target user not found: {target_username}")
            return False, "Target user not found"
        
        # Create target filename
        target_filename = f"from_{self.username}_{filename}"
        
        # Setup target paths
        target_shared_dir = self.server_dir / target_username / "shared_files"
        target_file_path = target_shared_dir / target_filename
        target_key_path = target_shared_dir / f"{target_filename}.key"
        target_meta_path = target_shared_dir / f"{target_filename}.meta"
        
        # Remove existing files if they exist
        if target_file_path.exists():
            target_file_path.unlink()
        if target_key_path.exists():
            target_key_path.unlink()
        if target_meta_path.exists():
            target_meta_path.unlink()
        
        try:
            # Read original file content
            with open(src_file_path, "r") as f:
                file_content = f.read()
            
            # Create metadata to track sharing relationship
            metadata = {
                "source_user": self.username,
                "source_file": str(src_file_path),
                "shared_at": timestamp
            }
            
            # Write shared file
            with open(target_file_path, "w") as f:
                f.write(file_content)
            
            # Write key
            with open(target_key_path, "w") as f:
                f.write(encrypted_key)
            
            # Write metadata
            with open(target_meta_path, "w") as f:
                json.dump(metadata, f)
            
            # Update sharing registry
            sharing_registry_path = self.server_dir / "sharing_registry.json"
            sharing_registry = {}
            
            if sharing_registry_path.exists():
                with open(sharing_registry_path, "r") as f:
                    sharing_registry = json.load(f)
            
            # Use full path of the file as key
            file_key = str(src_file_path)
            if file_key not in sharing_registry:
                sharing_registry[file_key] = []
            
            # Add new sharing record
            sharing_registry[file_key].append({
                "target_user": target_username,
                "target_file": str(target_file_path),
                "target_key": str(target_key_path),
                "target_meta": str(target_meta_path),
                "shared_at": timestamp
            })
            
            # Save updated registry
            with open(sharing_registry_path, "w") as f:
                json.dump(sharing_registry, f)
                
            self.log_action(self.username, "SHARE", f"Shared file {filename} with {target_username} (copy method)")
            return True, f"File shared successfully with {target_username}"
            
        except Exception as e:
            self.log_action(self.username, "SHARE_FAILED", f"Error sharing file: {e}")
            return False, f"Error sharing file: {e}"
    
    def list_files_from_server(self, signature: str, timestamp: str) -> Tuple[bool, List[str], List[str]]:
        """Get file list from server"""
        # Verify signature
        verification_data = f"{self.username}{timestamp}LIST"
        if not self.verify_signature(self.username, verification_data, signature):
            self.log_action(self.username, "LIST_FILES_FAILED", "Invalid signature")
            return False, [], []
        
        # Get user's own files
        own_files_dir = self.server_dir / self.username / "own_files"
        own_files = [f.name for f in own_files_dir.iterdir() 
                    if f.is_file() and not f.name.endswith(('.key', '.meta'))]
        
        # Get files shared with user
        shared_files_dir = self.server_dir / self.username / "shared_files"
        shared_files = []
        
        if shared_files_dir.exists():
            for f in shared_files_dir.iterdir():
                # Only include regular files, exclude key and metadata files
                if f.is_file() and not f.name.endswith(('.key', '.meta')):
                    shared_files.append(f.name)
        
        self.log_action(self.username, "LIST_FILES", f"Listed {len(own_files)} own files and {len(shared_files)} shared files")
        return True, own_files, shared_files
    
    def view_logs_from_server(self, signature: str, timestamp: str) -> Tuple[bool, str]:
        """Get system logs from server"""
        # Verify signature
        verification_data = f"{self.username}{timestamp}VIEWLOGS"
        if not self.verify_signature(self.username, verification_data, signature):
            self.log_action(self.username, "VIEW_LOGS_FAILED", "Invalid signature")
            return False, ""
        
        # Check if user is admin
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if self.username not in users or not users[self.username].get("is_admin", False):
            self.log_action(self.username, "VIEW_LOGS_FAILED", "Unauthorized access")
            return False, ""
        
        # Read logs
        log_file = self.server_dir / "log"
        if not log_file.exists():
            return True, "No logs available"
        
        with open(log_file, "r") as f:
            logs = f.read()
        
        self.log_action(self.username, "VIEW_LOGS", "Admin viewed system logs")
        return True, logs
    
    def get_user_public_key(self, username: str) -> Optional[str]:
        """Get user's public key"""
        users_file = self.server_dir / "users.json"
        if not users_file.exists():
            return None
        
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            return None
        
        return users[username]["public_key"]
    
    def verify_signature(self, username: str, data: str, signature: str) -> bool:
        """Verify user's digital signature"""
        try:
            public_key_pem = self.get_user_public_key(username)
            if not public_key_pem:
                return False
            
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
            
            # Verify signature
            public_key.verify(
                base64.b64decode(signature),
                data.encode(),
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def log_action(self, username: str, action: str, details: str = "") -> None:
        """Log user actions"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp},{username},{action},{details}\n"
        
        log_file = self.server_dir / "log"
        
        # Ensure log file exists
        if not log_file.exists():
            with open(log_file, "w") as f:
                f.write("Timestamp,Username,Action,Details\n")
        
        with open(log_file, "a") as f:
            f.write(log_entry)

    def get_encrypted_sub_master_key_from_server(self) -> str:
        """Get encrypted sub master key from server for current user"""
        if not self.username:
            raise ValueError("User not logged in")
            
        user_dir = self.server_dir / self.username / "keys"
        with open(user_dir / "sub_master_key.enc", "r") as f:
            return f.read()
            
    def change_password_on_server(self, new_password: str, encrypted_sub_master_key: str, 
                                encrypted_private_key: str, signature: str, 
                                timestamp: str) -> Tuple[bool, str]:
        """Send password change request to server"""
        # Verify signature
        verification_data = f"{self.username}{timestamp}CHANGE_PASSWORD"
        if not self.verify_signature(self.username, verification_data, signature):
            self.log_action(self.username, "PASSWORD_CHANGE_FAILED", "Invalid signature")
            return False, "Password change failed: Invalid signature"
        
        # Generate new server salt
        server_salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # Calculate new password hash with new salt
        password_hash = hashlib.sha256((new_password + server_salt).encode()).hexdigest()
        
        # Update user data in users.json
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if self.username not in users:
            return False, "Password change failed: User not found"
            
        users[self.username]["password_hash"] = password_hash
        users[self.username]["server_salt"] = server_salt
        
        with open(users_file, "w") as f:
            json.dump(users, f)
        
        # Update encrypted keys
        keys_dir = self.server_dir / self.username / "keys"
        
        with open(keys_dir / "sub_master_key.enc", "w") as f:
            f.write(encrypted_sub_master_key)
        
        with open(keys_dir / "private_key.enc", "w") as f:
            f.write(encrypted_private_key)
        
        self.log_action(self.username, "PASSWORD_CHANGED", "Password changed successfully")
        return True, "Password changed successfully"

    def change_password(self) -> None:
        """Change user password"""
        if not self.username:
            print("Please login first")
            return
        
        print("\n=== Change Password ===")
        
        # Get server salt for the current user
        success, server_salt = self.get_salt_from_server(self.username)
        if not success:
            print("Unable to verify current password: User data not found")
            return
        
        # Verify current password
        current_password = getpass.getpass("Enter your current password: ")
        
        # Calculate password hash and verify against stored hash
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        current_hash = hashlib.sha256((current_password + server_salt).encode()).hexdigest()
        
        if current_hash != users[self.username]["password_hash"]:
            print("Incorrect current password")
            return
        
        # Now that password is verified, proceed with password change
        # Input new password
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("New passwords do not match")
            return
        
        # Evaluate password strength
        valid, strength = self.evaluate_password_strength(new_password)
        if not valid:
            print(f"Password not strong enough: {strength}")
            return
        
        print(f"New password strength: {strength}")
        
        # Generate keys
        current_master_key = self.generate_master_key(current_password)
        new_master_key = self.generate_master_key(new_password)
        
        try:
            # Re-encrypt sub master key and private key with new master key
            encrypted_sub_master_key = self.encrypt_data(self.sub_master_key, new_master_key)
            
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            encrypted_private_key = self.encrypt_data(private_key_pem, new_master_key)
            
            # Get current timestamp
            timestamp = self.get_timestamp()
            
            # Create signature data
            signature_data = f"{self.username}{timestamp}CHANGE_PASSWORD"
            
            # Sign
            signature = self.sign_data(signature_data)
            
            # Send password change request to server
            success, message = self.change_password_on_server(
                new_password, encrypted_sub_master_key, encrypted_private_key, 
                signature, timestamp
            )
            
            print(message)
        except Exception as e:
            print(f"Error while changing password: {e}")

def show_menu(client) -> None:
    """Display menu based on login status"""
    print("\n==== Secure File System ====")
    
    if not client.username:
        # Display options for non-logged in users
        print("1. Register as Regular User")
        print("2. Register as Admin")
        print("3. Login")
        print("0. Exit")
    else:
        # Display options for logged in users
        print(f"Logged in as: {client.username}")
        print("1. Upload File")
        print("2. Download File")
        print("3. Delete File")
        print("4. Share File")
        print("5. List Files")
        print("6. Change Password")  # Password change option
        
        # Check if admin
        users_file = client.server_dir / "users.json"
        if users_file.exists():
            with open(users_file, "r") as f:
                users = json.load(f)
            if client.username in users and users[client.username].get("is_admin", False):
                print("7. View Logs (Admin)")
        
        print("8. Logout")
        print("0. Exit")
    
    print("============================")

def main():
    client = FileClient()
    
    while True:
        show_menu(client)
        choice = input("Enter your choice: ").strip()
        
        if not client.username:
            # Options for non-logged in users
            if choice == "1":
                client.register(is_admin=False)  # Register as regular user
            elif choice == "2":
                client.register(is_admin=True)   # Register as admin
            elif choice == "3":
                client.login()
            elif choice == "0":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        else:
            # Options for logged in users
            if choice == "1":
                client.upload_file()
            elif choice == "2":
                client.download_file()
            elif choice == "3":
                client.delete_file()
            elif choice == "4":
                client.share_file()
            elif choice == "5":
                own_files, shared_files = client.list_files()
                print("\n=== Your Files ===")
                if own_files:
                    for file in own_files:
                        print(file)
                else:
                    print("No files found")
                
                print("\n=== Shared With You ===")
                if shared_files:
                    for file in shared_files:
                        print(file)
                else:
                    print("No shared files")
            elif choice == "6":
                client.change_password()  # Call change password function
            elif choice == "7":
                # View logs (admin only)
                client.view_logs()
            elif choice == "8":
                print(f"Logged out from {client.username}")
                client.username = None
                client.sub_master_key = None
                client.private_key = None
                client.public_key = None
            elif choice == "0":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()