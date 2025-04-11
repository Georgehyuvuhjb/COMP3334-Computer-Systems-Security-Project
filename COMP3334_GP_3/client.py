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
import socket
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
    def __init__(self, server_host: str = "localhost", server_port: int = 8888):
        self.server_host = server_host
        self.server_port = server_port
        
        # Current user state
        self.username = None
        self.sub_master_key = None
        self.private_key = None
        self.public_key = None
        
        # Socket connection
        self.socket = None
    
    def connect_to_server(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            return True
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return False
    
    def close_connection(self):
        """Close connection to server"""
        if self.socket:
            self.socket.close()
            self.socket = None
    
    def send_request(self, command: str, data: Dict, auth: Optional[Dict] = None) -> Dict:
        """Send a request to the server and get response"""
        # Always verify connection is working before sending
        try:
            # Test if connection is still working by sending a small packet
            if self.socket:
                self.socket.sendall(b'')  # This will raise an exception if connection is broken
        except (ConnectionError, OSError, BrokenPipeError):
            # Connection is broken - close it and set to None to force reconnection
            self.close_connection()
        
        # Now attempt to connect if needed
        if not self.socket:
            if not self.connect_to_server():
                return {"status": "error", "message": "Failed to connect to server"}
        
        try:
            # Prepare request message
            request = {
                "command": command,
                "data": data
            }
            
            # Add auth if provided
            if auth:
                request["auth"] = auth
            
            # Convert request to JSON and send
            request_json = json.dumps(request).encode('utf-8')
            
            # Prefix with length (4 bytes)
            length_prefix = len(request_json).to_bytes(4, byteorder='big')
            
            # Send the message
            self.socket.sendall(length_prefix + request_json)
            
            # Receive response length
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                raise ConnectionError("Connection closed by server")
            
            # Convert length bytes to integer
            response_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive the full response
            response_data = b""
            remaining = response_length
            
            while remaining > 0:
                chunk = self.socket.recv(min(4096, remaining))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving response")
                response_data += chunk
                remaining -= len(chunk)
            
            # Parse response JSON
            response = json.loads(response_data.decode('utf-8'))
            return response
            
        except ConnectionError as e:
            print(f"Connection error: {e}")
            self.close_connection()  # Close the broken connection
            return {"status": "error", "message": str(e)}
        except Exception as e:
            print(f"Error in communication with server: {e}")
            return {"status": "error", "message": str(e)}
    
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
        
        # Generate keys for the cryptosystem
        master_key = self.generate_master_key(password)
        sub_master_key = os.urandom(32)  # Randomly generate sub-master key
        
        # Generate RSA key pair
        private_key, public_key = self.generate_keypair()
        
        # Serialize keys to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Encrypt keys with master key
        encrypted_sub_master_key = self.encrypt_data(sub_master_key, master_key)
        encrypted_private_key = self.encrypt_data(private_key_pem, master_key)
        
        # Check if username already exists
        check_response = self.send_request("CHECK_USERNAME", {"username": username})
        if check_response.get("status") == "success" and check_response.get("data", {}).get("exists"):
            print(f"Username '{username}' already exists")
            return
        
        # Generate new random server salt
        server_salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # Calculate password hash with the new salt
        password_hash = hashlib.sha256((password + server_salt).encode()).hexdigest()
        
        # Send registration request to server
        response = self.send_request(
            "REGISTER", 
            {
                "username": username,
                "password_hash": password_hash,
                "encrypted_sub_master_key": encrypted_sub_master_key,
                "encrypted_private_key": encrypted_private_key,
                "public_key": public_key_pem,
                "is_admin": is_admin,
                "server_salt": server_salt
            }
        )
        
        print(response["message"])
    
    def login(self) -> bool:
        """User login"""
        print("\n=== User Login ===")
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        
        # Get server salt
        response = self.send_request("GET_SALT", {"username": username})
        
        # Check if there was a connection error
        if response["status"] == "error":
            print("Server connection error. Please make sure the server is running.")
            return False
        
        # Continue with login process...
        server_salt = response["data"]["salt"]
        
        # Calculate password hash
        password_hash = hashlib.sha256((password + server_salt).encode()).hexdigest()
        
        # First stage login: password verification
        response = self.send_request(
            "LOGIN", 
            {
                "username": username,
                "password_hash": password_hash
            }
        )
        
        # Check again for connection errors
        if response["status"] == "error":
            if "connect" in response["message"].lower() or "connection" in response["message"].lower():
                print("Server connection error. Please make sure the server is running.")
                return False
            else:
                print("Invalid username or password")
                return False
        
        otp = response["data"]["otp"]
        
        # Display OTP window
        self.show_otp_window(otp)
        
        # Input OTP
        entered_otp = input("Enter the OTP code shown in the popup: ")
        
        # Second stage login: OTP verification
        response = self.send_request(
            "VERIFY_OTP", 
            {
                "username": username,
                "otp": entered_otp
            }
        )
        
        # Check again for connection errors
        if response["status"] == "error":
            if "connect" in response["message"].lower() or "connection" in response["message"].lower():
                print("Server connection error. Please make sure the server is running.")
                return False
            else:
                print("Invalid OTP or OTP expired")
                return False
        
        user_keys = response["data"]
        
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
        response = self.send_request(
            "UPLOAD",
            {
                "filename": filename,
                "encrypted_content": encrypted_content,
                "encrypted_key": encrypted_file_key,
                "content_hash": content_hash
            },
            {
                "username": self.username,
                "signature": signature,
                "timestamp": timestamp
            }
        )
        
        print(response["message"])

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
            response = self.send_request(
                "DOWNLOAD",
                {"filename": filename},
                {
                    "username": self.username,
                    "signature": signature,
                    "timestamp": timestamp
                }
            )
            
            if response["status"] != "success":
                print(f"Failed to download file: {response['message']}")
                return
            
            # Get encrypted content and key
            encrypted_content = response["data"]["encrypted_content"]
            encrypted_key = response["data"]["encrypted_key"]
            
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
            print(f"Error downloading file: {e}")
    
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
            
            if choice < 1 or choice > len(own_files):
                print("Invalid selection number")
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
            response = self.send_request(
                "DELETE",
                {"filename": filename},
                {
                    "username": self.username,
                    "signature": signature,
                    "timestamp": timestamp
                }
            )
            
            print(response["message"])
            
        except ValueError:
            print("Please enter a valid number")
        except Exception as e:
            print(f"Error deleting file: {e}")
    
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
            
            if choice < 1 or choice > len(own_files):
                print("Invalid selection number")
                return
            
            # Get selected filename
            filename = own_files[choice-1]
            
            # Input target user
            target_username = input("Enter username to share with: ").strip()
            
            if not target_username or target_username == self.username:
                print("Invalid target username")
                return
            
            # Get target user's public key
            response = self.send_request(
                "GET_PUBLIC_KEY", 
                {"target_username": target_username}
            )
            
            if response["status"] != "success":
                print(f"User {target_username} not found")
                return
                
            target_public_key = response["data"]["public_key"]
            
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
            response = self.send_request(
                "SHARE",
                {
                    "filename": filename,
                    "target_username": target_username,
                    "encrypted_key": encrypted_key_for_target
                },
                {
                    "username": self.username,
                    "signature": signature,
                    "timestamp": timestamp
                }
            )
            
            print(response["message"])
            
        except ValueError:
            print("Please enter a valid number")
        except Exception as e:
            print(f"Error sharing file: {e}")
    
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
        response = self.send_request(
            "LIST_FILES",
            {},
            {
                "username": self.username,
                "signature": signature,
                "timestamp": timestamp
            }
        )
        
        if response["status"] != "success":
            print(f"Failed to list files: {response['message']}")
            return [], []
        
        return response["data"]["own_files"], response["data"]["shared_files"]
    
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
        response = self.send_request(
            "VIEW_LOGS",
            {},
            {
                "username": self.username,
                "signature": signature,
                "timestamp": timestamp
            }
        )
        
        if response["status"] == "success":
            print("\n=== System Logs ===\n")
            print(response["data"]["logs"])
        else:
            print(response["message"])
    
    def change_password(self) -> None:
        """Change user password"""
        if not self.username:
            print("Please login first")
            return
        
        print("\n=== Change Password ===")
        
        # Get server salt for the current user
        response = self.send_request("GET_SALT", {"username": self.username})
        
        if response["status"] != "success":
            print("Unable to verify current password: User data not found")
            return
        
        server_salt = response["data"]["salt"]
        
        # Verify current password
        current_password = getpass.getpass("Enter your current password: ")
        
        # Calculate current password hash
        current_hash = hashlib.sha256((current_password + server_salt).encode()).hexdigest()
        
        # Verify current password with server (using login)
        verify_response = self.send_request(
            "LOGIN", 
            {
                "username": self.username,
                "password_hash": current_hash
            }
        )
        
        if verify_response["status"] != "success":
            print("Incorrect current password")
            return
        
        # Cancel the OTP process since we're just verifying the password
        
        # Now that password is verified, proceed with password change
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
            
            # Generate a new server salt
            new_server_salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            # Calculate new password hash using new salt
            new_password_hash = hashlib.sha256((new_password + new_server_salt).encode()).hexdigest()
            
            # Get current timestamp
            timestamp = self.get_timestamp()
            
            # Create signature data
            signature_data = f"{self.username}{timestamp}CHANGE_PASSWORD"
            
            # Sign
            signature = self.sign_data(signature_data)
            
            # Send password change request to server
            response = self.send_request(
                "CHANGE_PASSWORD",
                {
                    "new_password_hash": new_password_hash,
                    "server_salt": new_server_salt,
                    "encrypted_sub_master_key": encrypted_sub_master_key,
                    "encrypted_private_key": encrypted_private_key
                },
                {
                    "username": self.username,
                    "signature": signature,
                    "timestamp": timestamp
                }
            )
            
            print(response["message"])
        except Exception as e:
            print(f"Error while changing password: {e}")
            
def display_session_keys(client):
    """Display plaintext keys in memory for testing"""
    if not client.username:
        print("Not logged in, no keys to display")
        return
    
    print("\n===== Keys in Memory =====")
    print(f"User: {client.username}")
    
    # Display Sub-Master Key
    if client.sub_master_key:
        print("\n[Sub-Master Key]")
        print(f"Type: {type(client.sub_master_key)}")
        print(f"Length: {len(client.sub_master_key)} bytes")
        print(f"Hexadecimal: {client.sub_master_key.hex()}")
    
    # Display Private Key information
    if client.private_key:
        print("\n[Private Key]")
        private_numbers = client.private_key.private_numbers()
        print(f"Modulus (n): {private_numbers.public_numbers.n}")
        print(f"Public exponent (e): {private_numbers.public_numbers.e}")
        d_str = str(private_numbers.d)
        print(f"Private exponent (d) length: {len(d_str)} digits")
        print(f"Private exponent (d) first 10 digits: {d_str[:10]}...")
    
    # Display Public Key information
    if client.public_key:
        print("\n[Public Key]")
        public_numbers = client.public_key.public_numbers()
        print(f"Modulus (n): {public_numbers.n}")
        print(f"Public exponent (e): {public_numbers.e}")
    
    # Display a real file key for a random file if available
    if client.sub_master_key:
        # Get user's files
        own_files, _ = client.list_files()
        
        if own_files:
            # Select a random file from user's files
            import random
            random_file = random.choice(own_files)
            
            # Generate file key for this actual file
            file_key = client.generate_file_key(client.sub_master_key, random_file)
            
            print("\n[Real File Key]")
            print(f"File: {random_file}")
            print(f"Key: {file_key.hex()}")
        else:
            print("\n[File Key]")
            print("No files available to display key")

    print("===== End of Keys Display =====\n")

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
        print("1. Upload/Edit File")
        print("2. Download File")
        print("3. Delete File")
        print("4. Share File")
        print("5. List Files")
        print("6. Change Password")
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
                client.change_password()
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
                if client.username:
                    display_session_keys(client) #uncomment it for testing
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
    
    # Close connection before exiting
    client.close_connection()

if __name__ == "__main__":
    main()