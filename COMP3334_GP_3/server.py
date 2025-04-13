import pyotp
import qrcode
import io
import os
import json
import socket
import threading
import hashlib
import base64
import time
import random
import string
import hmac
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

class FileServer:
    def __init__(self, server_dir: str = "server", host: str = "localhost", port: int = 8888):
        self.server_dir = Path(server_dir)
        self.host = host
        self.port = port
        
        # Ensure server directory exists
        self.server_dir.mkdir(exist_ok=True)
        
        # Initialize server socket
        self.server_socket = None
    
    def start(self):
        """Start the server and listen for connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Set socket timeout to make accept() return periodically
        self.server_socket.settimeout(1.0)  # 1 second timeout
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Server started on {self.host}:{self.port}")
            print(f"Server data directory: {self.server_dir.absolute()}")
            print("Press Ctrl+C to shutdown server")
            
            # Variable to control server running state
            self.running = True
            
            # Main server loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"New connection from {client_address[0]}:{client_address[1]}")
                    
                    # Start a new thread to handle client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    # Continue loop after timeout to allow checking for interrupt signals
                    continue
                except Exception as e:
                    print(f"Error accepting connection: {e}")
                    
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, shutting down...")
        finally:
            self.shutdown()
        
    def shutdown(self):
        """Gracefully shutdown the server"""
        self.running = False
        print("Closing server socket...")
        if self.server_socket:
            self.server_socket.close()
        print("Server shutdown complete.")
    
    def handle_client(self, client_socket, address):
        """Handle communication with a client"""
        try:
            while True:
                # Receive message length (first 4 bytes)
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    print(f"Connection closed by client {address}")
                    break
                
                # Convert length bytes to integer
                message_length = int.from_bytes(length_bytes, byteorder='big')
                
                # Receive the full message
                message_data = b""
                remaining = message_length
                
                while remaining > 0:
                    chunk = client_socket.recv(min(4096, remaining))
                    if not chunk:
                        raise ConnectionError("Connection closed while receiving message")
                    message_data += chunk
                    remaining -= len(chunk)
                
                # Process message
                if message_data:
                    try:
                        # Decode JSON message
                        message = json.loads(message_data.decode('utf-8'))
                        
                        # Process command
                        response = self.process_command(message)
                        
                        # Send response
                        response_bytes = json.dumps(response).encode('utf-8')
                        length_prefix = len(response_bytes).to_bytes(4, byteorder='big')
                        client_socket.sendall(length_prefix + response_bytes)
                        
                    except json.JSONDecodeError:
                        print(f"Invalid JSON received from {address}")
                        error_response = {
                            "status": "error",
                            "message": "Invalid JSON format"
                        }
                        error_bytes = json.dumps(error_response).encode('utf-8')
                        length_prefix = len(error_bytes).to_bytes(4, byteorder='big')
                        client_socket.sendall(length_prefix + error_bytes)
                
        except ConnectionError as e:
            print(f"Connection error: {e}")
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"Connection closed with {address}")
    
    def process_command(self, message):
        """Process received commands from clients"""
        command = message.get("command", "")
        data = message.get("data", {})
        auth = message.get("auth", {})
        
        # Map commands to handler functions
        command_handlers = {
            "GET_SALT": self.handle_get_salt,
            "REGISTER": self.handle_register,
            "LOGIN": self.handle_login,
            "VERIFY_OTP": self.handle_verify_otp,
            "UPLOAD": self.handle_upload,
            "DOWNLOAD": self.handle_download,
            "DELETE": self.handle_delete,
            "SHARE": self.handle_share,
            "LIST_FILES": self.handle_list_files,
            "VIEW_LOGS": self.handle_view_logs,
            "GET_PUBLIC_KEY": self.handle_get_public_key,
            "CHANGE_PASSWORD": self.handle_change_password
        }
        
        handler = command_handlers.get(command)
        
        if handler:
            return handler(data, auth)
        else:
            return {
                "status": "error",
                "message": f"Unknown command: {command}"
            }
    
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
        except Exception as e:
            print(f"Signature verification error: {e}")
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
    
    def handle_get_salt(self, data, auth):
        """Handle request to get user salt"""
        username = data.get("username", "")
        
        users_file = self.server_dir / "users.json"
        if not users_file.exists():
            # No users exist yet
            return {
                "status": "error",
                "message": "User not found",
                "data": {
                    "salt": "NEW_USER_SALT"
                }
            }
        
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            # User not found
            return {
                "status": "error",
                "message": "User not found",
                "data": {
                    "salt": "NEW_USER_SALT"
                }
            }
        
        # User found, return their salt
        return {
            "status": "success",
            "message": "Salt retrieved",
            "data": {
                "salt": users[username]["server_salt"]
            }
        }
    
    def handle_register(self, data, auth):
        """Handle user registration"""
        username = data.get("username", "")
        password_hash = data.get("password_hash", "")
        encrypted_sub_master_key = data.get("encrypted_sub_master_key", "")
        encrypted_private_key = data.get("encrypted_private_key", "")
        public_key = data.get("public_key", "")
        is_admin = data.get("is_admin", False)
        server_salt = data.get("server_salt", "")
        
        # Validate required fields
        if not all([username, password_hash, encrypted_sub_master_key, 
                encrypted_private_key, public_key, server_salt]):
            return {
                "status": "error",
                "message": "Missing required registration data"
            }
        
        # Ensure server directory exists
        self.server_dir.mkdir(exist_ok=True)
        
        # Check if username already exists
        users_file = self.server_dir / "users.json"
        if users_file.exists():
            with open(users_file, "r") as f:
                users = json.load(f)
            
            if username in users:
                return {
                    "status": "error",
                    "message": "Username already exists"
                }
        else:
            # If users.json doesn't exist, create an empty dictionary
            users = {}
        
        # Generate TOTP secret for Google Authenticator
        totp_secret = pyotp.random_base32()
        
        # Create the otpauth URL for QR code
        totp_url = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username,
            issuer_name="SecureFileSystem"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_url)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        
        # Convert QR code to base64 string
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        # Store user data
        users[username] = {
            "password_hash": password_hash,
            "server_salt": server_salt,
            "public_key": public_key,
            "is_admin": is_admin,
            "totp_secret": totp_secret
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
        
        return {
            "status": "success",
            "message": f"{'Admin' if is_admin else 'User'} registered successfully",
            "data": {
                "totp_qr": qr_base64,
                "totp_secret": totp_secret
            }
        }

    def handle_login(self, data, auth):
        """Handle login request (first stage)"""
        username = data.get("username", "")
        password_hash = data.get("password_hash", "")
        
        # Validate required fields
        if not all([username, password_hash]):
            return {
                "status": "error",
                "message": "Missing required login data"
            }
        
        # Check user credentials
        users_file = self.server_dir / "users.json"
        if not users_file.exists():
            return {
                "status": "error",
                "message": "Invalid username or password"
            }
        
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            return {
                "status": "error",
                "message": "Invalid username or password"
            }
        
        if users[username]["password_hash"] != password_hash:
            self.log_action(username, "LOGIN_FAILED", "Invalid password")
            return {
                "status": "error",
                "message": "Invalid username or password"
            }
        
        # Log action
        self.log_action(username, "LOGIN_STAGE1", "Password verification successful, waiting for TOTP")
        
        # Password verified, now client should provide TOTP code
        return {
            "status": "success",
            "message": "Password verified, please enter authenticator code",
            "data": {
                "requires_totp": True
            }
        }   

    def handle_verify_otp(self, data, auth):
        """Handle TOTP verification (second stage login)"""
        username = data.get("username", "")
        totp_code = data.get("otp", "")
        
        # Validate required fields
        if not all([username, totp_code]):
            return {
                "status": "error",
                "message": "Missing username or authentication code"
            }
        
        # Read users data
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            return {
                "status": "error",
                "message": "User not found"
            }
        
        # Get TOTP secret
        totp_secret = users[username]["totp_secret"]
        
        try:
            # Verify TOTP code
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                self.log_action(username, "LOGIN_FAILED", "Invalid TOTP code")
                return {
                    "status": "error",
                    "message": "Invalid authentication code"
                }
            
            # Get user's encrypted keys
            user_dir = self.server_dir / username
            keys_dir = user_dir / "keys"
            
            if not keys_dir.exists():
                return {
                    "status": "error",
                    "message": "User keys not found"
                }
            
            user_keys = {}
            
            with open(keys_dir / "sub_master_key.enc", "r") as f:
                user_keys["encrypted_sub_master_key"] = f.read()
            
            with open(keys_dir / "private_key.enc", "r") as f:
                user_keys["encrypted_private_key"] = f.read()
            
            with open(keys_dir / "public_key", "r") as f:
                user_keys["public_key"] = f.read()
            
            # Log action
            self.log_action(username, "LOGIN_SUCCESS", "TOTP verification successful")
            
            return {
                "status": "success",
                "message": "Login successful",
                "data": user_keys
            }
                
        except Exception as e:
            self.log_action(username, "LOGIN_FAILED", f"TOTP verification error: {e}")
            return {
                "status": "error",
                "message": f"Error during authentication: {e}"
            }

    def handle_upload(self, data, auth):
        """Handle file upload"""
        username = auth.get("username", "")
        signature = auth.get("signature", "")
        timestamp = auth.get("timestamp", "")
        
        filename = data.get("filename", "")
        encrypted_content = data.get("encrypted_content", "")
        encrypted_key = data.get("encrypted_key", "")
        content_hash = data.get("content_hash", "")
        
        # Validate required fields
        if not all([username, signature, timestamp, filename, encrypted_content, encrypted_key]):
            return {
                "status": "error",
                "message": "Missing required upload data"
            }
        
        # Verify signature
        verification_data = f"{username}{timestamp}UPLOAD{content_hash}"
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "UPLOAD_FAILED", f"Invalid signature for file: {filename}")
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        try:
            # Save file and key
            user_files_dir = self.server_dir / username / "own_files"
            file_path = user_files_dir / filename
            key_path = user_files_dir / f"{filename}.key"
            
            with open(file_path, "w") as f:
                f.write(encrypted_content)
            
            with open(key_path, "w") as f:
                f.write(encrypted_key)
            
            self.log_action(username, "UPLOAD", f"File uploaded: {filename}")
            
            return {
                "status": "success",
                "message": "File uploaded successfully"
            }
        except Exception as e:
            self.log_action(username, "UPLOAD_FAILED", f"Error uploading file {filename}: {e}")
            return {
                "status": "error",
                "message": f"Error uploading file: {e}"
            }
    
    def handle_download(self, data, auth):
        """Handle file download"""
        username = auth.get("username", "")
        signature = auth.get("signature", "")
        timestamp = auth.get("timestamp", "")
        
        filename = data.get("filename", "")
        
        # Validate required fields
        if not all([username, signature, timestamp, filename]):
            return {
                "status": "error",
                "message": "Missing required download data"
            }
        
        # Verify signature
        verification_data = f"{username}{timestamp}DOWNLOAD{filename}"
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "DOWNLOAD_FAILED", f"Invalid signature for file: {filename}")
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # Check if it's user's own file or a shared file
        own_file_path = self.server_dir / username / "own_files" / filename
        own_key_path = self.server_dir / username / "own_files" / f"{filename}.key"
        
        shared_file_path = self.server_dir / username / "shared_files" / filename
        shared_key_path = self.server_dir / username / "shared_files" / f"{filename}.key"
        
        file_path = None
        key_path = None
        
        if own_file_path.exists() and own_key_path.exists():
            file_path = own_file_path
            key_path = own_key_path
        elif shared_file_path.exists() and shared_key_path.exists():
            file_path = shared_file_path
            key_path = shared_key_path
        else:
            self.log_action(username, "DOWNLOAD_FAILED", f"File not found: {filename}")
            return {
                "status": "error",
                "message": "File not found"
            }
        
        # Read file and key
        try:
            with open(file_path, "r") as f:
                file_content = f.read()
            
            with open(key_path, "r") as f:
                encrypted_key = f.read()
            
            self.log_action(username, "DOWNLOAD", f"File downloaded: {filename}")
            
            return {
                "status": "success",
                "message": "File downloaded successfully",
                "data": {
                    "encrypted_content": file_content,
                    "encrypted_key": encrypted_key
                }
            }
        except FileNotFoundError:
            self.log_action(username, "DOWNLOAD_FAILED", f"File or key not accessible: {filename}")
            return {
                "status": "error",
                "message": "File or key not accessible"
            }
    
    def handle_delete(self, data, auth):
        """Handle file deletion"""
        username = auth.get("username", "")
        signature = auth.get("signature", "")
        timestamp = auth.get("timestamp", "")
        
        filename = data.get("filename", "")
        
        # Validate required fields
        if not all([username, signature, timestamp, filename]):
            return {
                "status": "error",
                "message": "Missing required deletion data"
            }
        
        # Verify signature
        verification_data = f"{username}{timestamp}DELETE{filename}"
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "DELETE_FAILED", f"Invalid signature for file: {filename}")
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # Check if file exists
        file_path = self.server_dir / username / "own_files" / filename
        key_path = self.server_dir / username / "own_files" / f"{filename}.key"
        
        if not file_path.exists() or not key_path.exists():
            self.log_action(username, "DELETE_FAILED", f"File not found: {filename}")
            return {
                "status": "error",
                "message": "File not found"
            }
        
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
                self.log_action(username, "DELETE_REGISTRY_ERROR", 
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
                    
                self.log_action(username, "DELETE_SHARED", 
                              f"Removed shared copy from user {target_user}")
            except Exception as e:
                self.log_action(username, "DELETE_SHARED_FAILED", 
                              f"Failed to remove shared copy: {e}")
        
        # Delete original file
        try:
            file_path.unlink()
            key_path.unlink()
            
            # Log deletion
            num_shared = len(shared_files_to_remove)
            if num_shared > 0:
                self.log_action(username, "DELETE", f"File deleted: {filename} (and {num_shared} shared copies)")
                return {
                    "status": "success",
                    "message": f"File deleted successfully (including {num_shared} shared copies)"
                }
            else:
                self.log_action(username, "DELETE", f"File deleted: {filename}")
                return {
                    "status": "success",
                    "message": "File deleted successfully"
                }
        except Exception as e:
            self.log_action(username, "DELETE_FAILED", f"Error deleting file {filename}: {e}")
            return {
                "status": "error",
                "message": f"Error deleting file: {e}"
            }
    
    def handle_share(self, data, auth):
        """Handle file sharing"""
        username = auth.get("username", "")
        signature = auth.get("signature", "")
        timestamp = auth.get("timestamp", "")
        
        filename = data.get("filename", "")
        target_username = data.get("target_username", "")
        encrypted_key = data.get("encrypted_key", "")
        
        # Validate required fields
        if not all([username, signature, timestamp, filename, target_username, encrypted_key]):
            return {
                "status": "error",
                "message": "Missing required sharing data"
            }
        
        # Verify signature
        verification_data = f"{username}{timestamp}SHARE{filename}{target_username}"
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "SHARE_FAILED", f"Invalid signature for sharing file: {filename}")
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # Check if file exists
        src_file_path = self.server_dir / username / "own_files" / filename
        src_key_path = self.server_dir / username / "own_files" / f"{filename}.key"
        if not src_file_path.exists() or not src_key_path.exists():
            self.log_action(username, "SHARE_FAILED", f"File not found: {filename}")
            return {
                "status": "error",
                "message": "File not found"
            }
        
        # Check if target user exists
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if target_username not in users:
            self.log_action(username, "SHARE_FAILED", f"Target user not found: {target_username}")
            return {
                "status": "error",
                "message": "Target user not found"
            }
        
        # Create target filename
        target_filename = f"from_{username}_{filename}"
        
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
                "source_user": username,
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
                
            self.log_action(username, "SHARE", f"Shared file {filename} with {target_username} (copy method)")
            
            return {
                "status": "success",
                "message": f"File shared successfully with {target_username}"
            }
                
        except Exception as e:
            self.log_action(username, "SHARE_FAILED", f"Error sharing file: {e}")
            return {
                "status": "error",
                "message": f"Error sharing file: {e}"
            }
    
    def handle_list_files(self, data, auth):
        """Handle file listing"""
        username = auth.get("username", "")
        signature = auth.get("signature", "")
        timestamp = auth.get("timestamp", "")
        
        # Validate required fields
        if not all([username, signature, timestamp]):
            return {
                "status": "error",
                "message": "Missing required authentication data"
            }
        
        # Verify signature
        verification_data = f"{username}{timestamp}LIST"
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "LIST_FILES_FAILED", "Invalid signature")
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # Get user's own files
        own_files_dir = self.server_dir / username / "own_files"
        own_files = [f.name for f in own_files_dir.iterdir() 
                    if f.is_file() and not f.name.endswith(('.key', '.meta'))]
        
        # Get files shared with user
        shared_files_dir = self.server_dir / username / "shared_files"
        shared_files = []
        
        if shared_files_dir.exists():
            for f in shared_files_dir.iterdir():
                # Only include regular files, exclude key and metadata files
                if f.is_file() and not f.name.endswith(('.key', '.meta')):
                    shared_files.append(f.name)
        
        self.log_action(username, "LIST_FILES", f"Listed {len(own_files)} own files and {len(shared_files)} shared files")
        
        return {
            "status": "success",
            "message": "Files listed successfully",
            "data": {
                "own_files": own_files,
                "shared_files": shared_files
            }
        }
    
    def handle_view_logs(self, data, auth):
        """Handle logs viewing (admin only)"""
        username = auth.get("username", "")
        signature = auth.get("signature", "")
        timestamp = auth.get("timestamp", "")
        
        # Validate required fields
        if not all([username, signature, timestamp]):
            return {
                "status": "error",
                "message": "Missing required authentication data"
            }
        
        # Verify signature
        verification_data = f"{username}{timestamp}VIEWLOGS"
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "VIEW_LOGS_FAILED", "Invalid signature")
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # Check if user is admin
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users or not users[username].get("is_admin", False):
            self.log_action(username, "VIEW_LOGS_FAILED", "Unauthorized access")
            return {
                "status": "error",
                "message": "You don't have permission to view logs"
            }
        
        # Read logs
        log_file = self.server_dir / "log"
        if not log_file.exists():
            return {
                "status": "success",
                "message": "No logs available",
                "data": {
                    "logs": ""
                }
            }
        
        with open(log_file, "r") as f:
            logs = f.read()
        
        self.log_action(username, "VIEW_LOGS", "Admin viewed system logs")
        
        return {
            "status": "success",
            "message": "Logs retrieved successfully",
            "data": {
                "logs": logs
            }
        }
    
    def handle_get_public_key(self, data, auth):
        """Handle request to get a user's public key"""
        username = auth.get("username", "")  # Requester
        target_username = data.get("target_username", "")
        
        # Validate required fields
        if not target_username:
            return {
                "status": "error",
                "message": "Missing target username"
            }
        
        users_file = self.server_dir / "users.json"
        if not users_file.exists():
            return {
                "status": "error",
                "message": "User database not found"
            }
        
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if target_username not in users:
            return {
                "status": "error",
                "message": f"User {target_username} not found"
            }
        
        public_key = users[target_username]["public_key"]
        
        if username:  # If authenticated request, log it
            self.log_action(username, "GET_PUBLIC_KEY", f"Retrieved public key of {target_username}")
        
        return {
            "status": "success",
            "message": f"Public key for {target_username} retrieved",
            "data": {
                "public_key": public_key
            }
        }

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
    
    def handle_change_password(self, data, auth):
        """Handle password change request"""
        username = auth.get("username", "")
        signature = auth.get("signature", "")
        timestamp = auth.get("timestamp", "")
        
        new_password_hash = data.get("new_password_hash", "")
        server_salt = data.get("server_salt", "")
        encrypted_sub_master_key = data.get("encrypted_sub_master_key", "")
        encrypted_private_key = data.get("encrypted_private_key", "")
        
        # Validate required fields
        if not all([username, signature, timestamp, new_password_hash, server_salt, 
                   encrypted_sub_master_key, encrypted_private_key]):
            return {
                "status": "error",
                "message": "Missing required password change data"
            }
        
        # Verify signature
        verification_data = f"{username}{timestamp}CHANGE_PASSWORD"
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "PASSWORD_CHANGE_FAILED", "Invalid signature")
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # Update user data in users.json
        users_file = self.server_dir / "users.json"
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            return {
                "status": "error",
                "message": "User not found"
            }
                
        users[username]["password_hash"] = new_password_hash
        users[username]["server_salt"] = server_salt
        
        with open(users_file, "w") as f:
            json.dump(users, f)
        
        # Update encrypted keys
        keys_dir = self.server_dir / username / "keys"
        
        with open(keys_dir / "sub_master_key.enc", "w") as f:
            f.write(encrypted_sub_master_key)
        
        with open(keys_dir / "private_key.enc", "w") as f:
            f.write(encrypted_private_key)
        
        self.log_action(username, "PASSWORD_CHANGED", "Password changed successfully")
        
        return {
            "status": "success",
            "message": "Password changed successfully"
        }

if __name__ == "__main__":
    server = FileServer()
    server.start()