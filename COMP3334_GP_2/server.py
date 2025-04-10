import os
import json
import hashlib
import random
import string
import time
import base64
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

class FileServer:
    def __init__(self, server_dir: str = "server"):
        self.server_dir = Path(server_dir)
        self.users_file = self.server_dir / "users.json"
        self.log_file = self.server_dir / "log"
        
        # Ensure server directory structure exists
        self.server_dir.mkdir(exist_ok=True)
        
        # Load user data, initialize if doesn't exist
        if not self.users_file.exists():
            with open(self.users_file, "w") as f:
                json.dump({}, f)
        
        # Ensure log file exists
        if not self.log_file.exists():
            with open(self.log_file, "w") as f:
                f.write("Timestamp,Username,Action,Details\n")
        
        # Store currently active OTP codes
        self.active_otps = {}  # Format: {username: (otp, expiry_time)}
    
    def log_action(self, username: str, action: str, details: str = "") -> None:
        """Log user actions to the log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp},{username},{action},{details}\n"
        
        with open(self.log_file, "a") as f:
            f.write(log_entry)
    
    def get_users(self) -> Dict:
        """Get all user data"""
        with open(self.users_file, "r") as f:
            return json.load(f)
    
    def save_users(self, users: Dict) -> None:
        """Save user data"""
        with open(self.users_file, "w") as f:
            json.dump(users, f)
    
    def register_user(self, username: str, password_hash: str, 
                      encrypted_sub_master_key: str, encrypted_private_key: str, 
                      public_key: str) -> Tuple[bool, str]:
        """Register new user"""
        # Check if username already exists
        users = self.get_users()
        if username in users:
            return False, "Username already exists"
        
        # Generate server salt
        server_salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # Store user data
        users[username] = {
            "password_hash": password_hash,
            "server_salt": server_salt,
            "public_key": public_key,
            "is_admin": False  # Default non-admin
        }
        self.save_users(users)
        
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
        
        self.log_action(username, "REGISTER", "User registration successful")
        return True, "User registered successfully"
    
    def get_salt(self, username: str) -> Tuple[bool, str]:
        """Get user's salt value"""
        users = self.get_users()
        if username not in users:
            return False, "User not found"
        
        return True, users[username]["server_salt"]
    
    def login(self, username: str, password_hash: str) -> Tuple[bool, str]:
        """Phase 1 login: Verify password"""
        users = self.get_users()
        
        if username not in users:
            return False, "Invalid username or password"
        
        if users[username]["password_hash"] != password_hash:
            self.log_action(username, "LOGIN_FAILED", "Invalid password")
            return False, "Invalid username or password"
        
        # Generate OTP code
        otp = ''.join(random.choices(string.digits, k=6))
        expiry_time = time.time() + 60  # Expires after 60 seconds
        self.active_otps[username] = (otp, expiry_time)
        
        self.log_action(username, "LOGIN_STAGE1", "Password verification successful, OTP generated")
        return True, otp
    
    def verify_otp(self, username: str, otp: str) -> Tuple[bool, Dict]:
        """Phase 2 login: Verify OTP"""
        if username not in self.active_otps:
            return False, {}
        
        stored_otp, expiry_time = self.active_otps[username]
        
        # Check if OTP is expired
        if time.time() > expiry_time:
            del self.active_otps[username]
            return False, {}
        
        # Check if OTP is correct
        if otp != stored_otp:
            return False, {}
        
        # OTP verification successful, clear OTP
        del self.active_otps[username]
        
        # Return user's encrypted keys
        user_dir = self.server_dir / username
        keys_dir = user_dir / "keys"
        
        user_keys = {}
        with open(keys_dir / "sub_master_key.enc", "r") as f:
            user_keys["encrypted_sub_master_key"] = f.read()
        
        with open(keys_dir / "private_key.enc", "r") as f:
            user_keys["encrypted_private_key"] = f.read()
        
        with open(keys_dir / "public_key", "r") as f:
            user_keys["public_key"] = f.read()
        
        self.log_action(username, "LOGIN_SUCCESS", "OTP verification successful")
        return True, user_keys
    
    def verify_signature(self, username: str, data: str, signature: str) -> bool:
        """Verify user's digital signature"""
        try:
            users = self.get_users()
            if username not in users:
                return False
            
            public_key_pem = users[username]["public_key"]
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
            
            # Verify signature
            public_key.verify(
                base64.b64decode(signature),
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False
    
    def upload_file(self, username: str, filename: str, file_content: str, 
                   encrypted_key: str, signature: str, timestamp: str) -> Tuple[bool, str]:
        """Upload file"""
        # Create verification data
        verification_data = f"{username}{timestamp}UPLOAD{hashlib.sha256(file_content.encode()).hexdigest()}"
        
        # Verify signature
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "UPLOAD_FAILED", f"Invalid signature for file: {filename}")
            return False, "Invalid signature"
        
        # Save file and key
        user_files_dir = self.server_dir / username / "own_files"
        file_path = user_files_dir / filename
        key_path = user_files_dir / f"{filename}.key"
        
        with open(file_path, "w") as f:
            f.write(file_content)
        
        with open(key_path, "w") as f:
            f.write(encrypted_key)
        
        self.log_action(username, "UPLOAD", f"File uploaded: {filename}")
        return True, "File uploaded successfully"
    
    def download_file(self, username: str, filename: str, signature: str, 
                     timestamp: str) -> Tuple[bool, str, str]:
        """Download file"""
        # Create verification data
        verification_data = f"{username}{timestamp}DOWNLOAD{filename}"
        
        # Verify signature
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "DOWNLOAD_FAILED", f"Invalid signature for file: {filename}")
            return False, "", ""
        
        # Check if it's user's own file or shared file
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
            return False, "", ""
        
        # Read file and key
        with open(file_path, "r") as f:
            file_content = f.read()
        
        with open(key_path, "r") as f:
            encrypted_key = f.read()
        
        self.log_action(username, "DOWNLOAD", f"File downloaded: {filename}")
        return True, file_content, encrypted_key
    
    def delete_file(self, username: str, filename: str, signature: str, 
                   timestamp: str) -> Tuple[bool, str]:
        """Delete file"""
        # Create verification data
        verification_data = f"{username}{timestamp}DELETE{filename}"
        
        # Verify signature
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "DELETE_FAILED", f"Invalid signature for file: {filename}")
            return False, "Invalid signature"
        
        # Check if it's user's own file
        file_path = self.server_dir / username / "own_files" / filename
        key_path = self.server_dir / username / "own_files" / f"{filename}.key"
        
        if not file_path.exists() or not key_path.exists():
            self.log_action(username, "DELETE_FAILED", f"File not found: {filename}")
            return False, "File not found"
        
        # Delete file and key
        file_path.unlink()
        key_path.unlink()
        
        self.log_action(username, "DELETE", f"File deleted: {filename}")
        return True, "File deleted successfully"
    
    def share_file(self, username: str, filename: str, target_username: str, 
                  encrypted_key: str, signature: str, timestamp: str) -> Tuple[bool, str]:
        """Share file"""
        # Create verification data
        verification_data = f"{username}{timestamp}SHARE{filename}{target_username}"
        
        # Verify signature
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "SHARE_FAILED", f"Invalid signature for sharing file: {filename}")
            return False, "Invalid signature"
        
        # Check if file exists
        src_file_path = self.server_dir / username / "own_files" / filename
        if not src_file_path.exists():
            self.log_action(username, "SHARE_FAILED", f"File not found: {filename}")
            return False, "File not found"
        
        # Check if target user exists
        users = self.get_users()
        if target_username not in users:
            self.log_action(username, "SHARE_FAILED", f"Target user not found: {target_username}")
            return False, "Target user not found"
        
        # Create target filename to prevent naming conflicts
        target_filename = f"from_{username}_{filename}"
        
        # Copy file to target user's shared folder
        target_file_path = self.server_dir / target_username / "shared_files" / target_filename
        target_key_path = self.server_dir / target_username / "shared_files" / f"{target_filename}.key"
        
        # Read original file content
        with open(src_file_path, "r") as f:
            file_content = f.read()
        
        # Write file and encrypted key to target user's directory
        with open(target_file_path, "w") as f:
            f.write(file_content)
        
        with open(target_key_path, "w") as f:
            f.write(encrypted_key)
        
        self.log_action(username, "SHARE", f"Shared file {filename} with {target_username}")
        return True, f"File shared successfully with {target_username}"
    
    def list_files(self, username: str, signature: str, timestamp: str) -> Tuple[bool, List[str], List[str]]:
        """List user's files"""
        # Create verification data
        verification_data = f"{username}{timestamp}LIST"
        
        # Verify signature
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "LIST_FILES_FAILED", "Invalid signature")
            return False, [], []
        
        # Get user's own files
        own_files_dir = self.server_dir / username / "own_files"
        own_files = [f.name for f in own_files_dir.iterdir() 
                    if f.is_file() and not f.name.endswith('.key')]
        
        # Get files shared with user
        shared_files_dir = self.server_dir / username / "shared_files"
        shared_files = [f.name for f in shared_files_dir.iterdir() 
                       if f.is_file() and not f.name.endswith('.key')]
        
        self.log_action(username, "LIST_FILES", f"Listed {len(own_files)} own files and {len(shared_files)} shared files")
        return True, own_files, shared_files
    
    def view_logs(self, username: str, signature: str, timestamp: str) -> Tuple[bool, str]:
        """View system logs (admin only)"""
        # Create verification data
        verification_data = f"{username}{timestamp}VIEWLOGS"
        
        # Verify signature
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "VIEW_LOGS_FAILED", "Invalid signature")
            return False, "Invalid signature"
        
        # Check if user is admin
        users = self.get_users()
        if username not in users or not users[username].get("is_admin", False):
            self.log_action(username, "VIEW_LOGS_FAILED", "Unauthorized access")
            return False, "Unauthorized access"
        
        # Read logs
        with open(self.log_file, "r") as f:
            logs = f.read()
        
        self.log_action(username, "VIEW_LOGS", "Admin viewed system logs")
        return True, logs
    
    def set_admin(self, username: str, is_admin: bool) -> Tuple[bool, str]:
        """Set user's admin status"""
        users = self.get_users()
        
        if username not in users:
            return False, "User not found"
        
        users[username]["is_admin"] = is_admin
        self.save_users(users)
        
        status = "granted" if is_admin else "revoked"
        self.log_action("SYSTEM", "ADMIN_STATUS_CHANGE", f"Admin status {status} for {username}")
        return True, f"Admin status {status} for {username}"
    
    def change_password(self, username: str, new_password: str, 
                    encrypted_sub_master_key: str, encrypted_private_key: str,
                    signature: str, timestamp: str) -> Tuple[bool, str]:
        """Change user password"""
        # Create verification data
        verification_data = f"{username}{timestamp}CHANGE_PASSWORD"
        
        # Verify signature
        if not self.verify_signature(username, verification_data, signature):
            self.log_action(username, "PASSWORD_CHANGE_FAILED", "Invalid signature")
            return False, "Invalid signature"
        
        # Generate new server salt
        server_salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # Calculate new password hash
        password_hash = hashlib.sha256((new_password + server_salt).encode()).hexdigest()
        
        # Update user data
        users = self.get_users()
        users[username]["password_hash"] = password_hash
        users[username]["server_salt"] = server_salt
        self.save_users(users)
        
        # Update encrypted keys
        keys_dir = self.server_dir / username / "keys"
        
        with open(keys_dir / "sub_master_key.enc", "w") as f:
            f.write(encrypted_sub_master_key)
        
        with open(keys_dir / "private_key.enc", "w") as f:
            f.write(encrypted_private_key)
        
        self.log_action(username, "PASSWORD_CHANGED", "Password changed successfully")
        return True, "Password changed successfully"

def main():
    server = FileServer()
    print("Server initialized. Server directory:", server.server_dir)
    print("Server is running. Use client.py to interact with the server.")
    
    # Add a simple loop to keep server running
    try:
        print("Press Ctrl+C to stop the server...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nServer shutting down...")

if __name__ == "__main__":
    main()