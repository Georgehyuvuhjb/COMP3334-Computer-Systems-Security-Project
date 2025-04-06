# server.py
import socketserver
import json
import struct
import os
import uuid
import datetime
import hashlib
import re
import sys
import traceback
import hmac

# ==================================================
# Section: Configuration
# ==================================================
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999
BUFFER_SIZE = 4096
# TODO: CHANGE THIS! This is extremely insecure. Use environment variables or a config file.
SHARED_SECRET = "insecure_default_secret"
SERVER_METADATA_PATH = './server_metadata/' # Run server in project root
SERVER_FILE_STORAGE_PATH = './server_file_storage/' # Run server in project root
USERS_DIR = os.path.join(SERVER_METADATA_PATH, 'users/')
AUDIT_LOG_FILE = os.path.join(SERVER_METADATA_PATH, 'audit.log')
# TODO: Add file size limits, password complexity rules etc.
MAX_MSG_SIZE = 100 * 1024 * 1024 # Max JSON message size (e.g., 100MB)
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024 # Max file size (e.g., 1GB) - Implement check!
HASH_ITERATIONS = 2600 # Iterations for PBKDF2

# ==================================================
# Section: Utilities
# ==================================================
def is_safe_filename(filename, allow_uuid=False):
    """
    Checks if a filename is safe. Needs significant improvement for production.
    Set allow_uuid=True for internally generated UUIDs which might have hyphens.
    TODO: Enhance this significantly (check reserved names, length, encoding issues, etc.)
    """
    if not filename or not isinstance(filename, str):
        return False
    if '\0' in filename or '/' in filename or '\\' in filename or '..' in filename:
        print(f"[Security Alert] Unsafe characters or path traversal attempt in filename: {filename}")
        return False

    # Basic pattern: letters, numbers, underscore, dot, hyphen (hyphen only if allow_uuid)
    safe_pattern = r'^[a-zA-Z0-9_.]+$'
    if allow_uuid:
        safe_pattern = r'^[a-zA-Z0-9_.-]+$' # Allow hyphen for UUIDs

    if not re.match(safe_pattern, filename):
         # Allow specific extensions like .enc and .meta for internal use
         if not (filename.endswith(".enc") or filename.endswith(".meta")) or not re.match(safe_pattern[:-1] + r'(\.enc|\.meta)$', filename) :
             print(f"[Security Alert] Filename validation failed: {filename}")
             return False

    # Length check
    if len(filename) > 255:
         print(f"[Security Alert] Filename too long: {filename}")
         return False
    # TODO: Add checks for reserved filenames (CON, PRN, etc. on Windows)

    return True

def ensure_dir_exists(dir_path):
    """Ensures a directory exists."""
    if not os.path.exists(dir_path):
        try:
            os.makedirs(dir_path, exist_ok=True)
            print(f"Created directory: {dir_path}")
        except OSError as e:
            print(f"CRITICAL: Error creating directory {dir_path}: {e}")
            raise

# ==================================================
# Section: File System Store (No Locks - Relies on Serial Execution)
# ==================================================
def initialize_storage():
    """Initializes server storage directories."""
    print("Initializing server storage...")
    try:
        ensure_dir_exists(SERVER_METADATA_PATH)
        ensure_dir_exists(USERS_DIR)
        ensure_dir_exists(SERVER_FILE_STORAGE_PATH)
        # Create audit log if it doesn't exist
        if not os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.datetime.now().isoformat()} | System | STARTUP | SUCCESS | Audit log created.\n")
        print("Storage directories ensured.")
        log_audit("System", "STARTUP", True, "Storage initialized.")
    except Exception as e:
        print(f"FATAL: Could not initialize storage directories: {e}")
        log_audit("System", "STARTUP", False, f"Storage initialization failed: {e}")
        sys.exit(1)

def log_action_to_file(log_entry):
    """Appends a log entry to the audit file."""
    try:
        with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')
    except IOError as e:
        print(f"ERROR writing to audit log file {AUDIT_LOG_FILE}: {e}")

def user_exists(username):
    """Checks if a user exists."""
    if not is_safe_filename(username): return False
    user_file = os.path.join(USERS_DIR, f"{username}.json")
    return os.path.isfile(user_file)

def add_user(username, user_data):
    """Adds a new user. Raises ValueError if invalid or exists."""
    if not is_safe_filename(username): raise ValueError("Invalid username format.")
    if user_exists(username): raise ValueError(f"User '{username}' already exists.")
    user_file = os.path.join(USERS_DIR, f"{username}.json")
    try:
        with open(user_file, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, indent=4)
        return True
    except IOError as e:
        print(f"ERROR adding user {username}: {e}")
        # Clean up potentially created empty file?
        if os.path.exists(user_file) and os.path.getsize(user_file) == 0:
             try: os.remove(user_file)
             except OSError: pass
        raise IOError(f"Failed to save user data for {username}") # Re-raise as specific error

def get_user_data(username):
    """Gets user data."""
    if not user_exists(username): return None
    user_file = os.path.join(USERS_DIR, f"{username}.json")
    try:
        with open(user_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"ERROR reading user data for {username}: {e}")
        return None

def save_file_metadata(file_uuid, metadata):
    """Saves file metadata."""
    if not isinstance(file_uuid, str) or not is_safe_filename(file_uuid + ".meta", allow_uuid=True):
        print(f"ERROR: Invalid file UUID format for metadata: {file_uuid}")
        return False
    meta_path = os.path.join(SERVER_FILE_STORAGE_PATH, f"{file_uuid}.meta")
    try:
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4)
        return True
    except IOError as e:
        print(f"ERROR saving metadata for {file_uuid}: {e}")
        return False

def get_file_metadata(file_uuid):
    """Gets file metadata."""
    if not isinstance(file_uuid, str) or not is_safe_filename(file_uuid + ".meta", allow_uuid=True): return None
    meta_path = os.path.join(SERVER_FILE_STORAGE_PATH, f"{file_uuid}.meta")
    if not os.path.isfile(meta_path): return None
    try:
        with open(meta_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"ERROR reading metadata for {file_uuid}: {e}")
        return None

def get_file_content_path(file_uuid):
    """Gets the path to the encrypted file content."""
    if not isinstance(file_uuid, str) or not is_safe_filename(file_uuid + ".enc", allow_uuid=True): return None
    enc_path = os.path.join(SERVER_FILE_STORAGE_PATH, f"{file_uuid}.enc")
    if os.path.isfile(enc_path):
        return enc_path
    else:
        return None

def delete_file_data(file_uuid):
    """Deletes file content and metadata."""
    if not isinstance(file_uuid, str) or not is_safe_filename(file_uuid + ".enc", allow_uuid=True):
        print(f"ERROR: Invalid file UUID format for deletion: {file_uuid}")
        return False
    enc_path = os.path.join(SERVER_FILE_STORAGE_PATH, f"{file_uuid}.enc")
    meta_path = os.path.join(SERVER_FILE_STORAGE_PATH, f"{file_uuid}.meta")
    deleted = False
    try:
        if os.path.isfile(enc_path):
            os.remove(enc_path)
            print(f"Deleted content file: {enc_path}")
            deleted = True
        if os.path.isfile(meta_path):
            os.remove(meta_path)
            print(f"Deleted metadata file: {meta_path}")
            deleted = True
        return deleted # Return True if either was deleted
    except OSError as e:
        print(f"ERROR deleting file data for {file_uuid}: {e}")
        return False

def list_all_files_metadata():
    """Lists metadata for all files (inefficient)."""
    all_metadata = []
    try:
        for filename in os.listdir(SERVER_FILE_STORAGE_PATH):
            # Check if it looks like a valid meta file before proceeding
            if filename.endswith(".meta") and is_safe_filename(filename, allow_uuid=True):
                file_uuid = filename[:-5]
                metadata = get_file_metadata(file_uuid)
                if metadata:
                    metadata['uuid'] = file_uuid
                    all_metadata.append(metadata)
    except OSError as e:
        print(f"ERROR listing files in {SERVER_FILE_STORAGE_PATH}: {e}")
    return all_metadata

# ==================================================
# Section: Audit Logger
# ==================================================
def log_audit(username, action, success, details=""):
    """Records an audit log entry."""
    timestamp = datetime.datetime.now().isoformat()
    status = "SUCCESS" if success else "FAILURE"
    # Basic sanitization
    username = str(username).replace('|', '_').replace('\n', ' ')
    action = str(action).replace('|', '_').replace('\n', ' ')
    details = str(details).replace('|', '_').replace('\n', ' ')
    log_entry = f"{timestamp} | User: {username} | Action: {action} | Status: {status} | Details: {details}"
    try:
        log_action_to_file(log_entry)
    except Exception as e:
        print(f"ERROR: Failed to write audit log: {e}")

# ==================================================
# Section: Network Communication
# ==================================================
def send_message(connection, message):
    """Sends a JSON message with length prefix."""
    try:
        json_message = json.dumps(message).encode('utf-8')
        message_len = len(json_message)
        if message_len > MAX_MSG_SIZE:
             print(f"ERROR: Attempting to send message larger than MAX_MSG_SIZE ({message_len} > {MAX_MSG_SIZE})")
             log_audit("System", "SEND_MSG_ERR", False, "Message size exceeded limit")
             return False
        len_prefix = struct.pack('>I', message_len)
        connection.sendall(len_prefix)
        connection.sendall(json_message)
        # print(f"[Net Send] {message}") # Debug
        return True
    except (OSError, BrokenPipeError, json.JSONDecodeError, TypeError) as e:
        print(f"ERROR sending message: {e}")
        return False

def receive_message(connection):
    """Receives a JSON message with length prefix."""
    try:
        len_prefix_data = connection.recv(4)
        if not len_prefix_data or len(len_prefix_data) < 4: return None
        message_len = struct.unpack('>I', len_prefix_data)[0]

        if message_len > MAX_MSG_SIZE:
             print(f"ERROR: Incoming message length too large: {message_len}. Closing connection.")
             log_audit("System", "RECV_MSG_ERR", False, f"Message size {message_len} exceeded limit {MAX_MSG_SIZE}")
             # TODO: Gracefully close connection?
             return None # Or raise an exception

        received_data = b''
        while len(received_data) < message_len:
            chunk = connection.recv(min(message_len - len(received_data), BUFFER_SIZE))
            if not chunk: return None # Connection closed
            received_data += chunk

        decoded_msg = json.loads(received_data.decode('utf-8'))
        # print(f"[Net Recv] {decoded_msg}") # Debug
        return decoded_msg
    except (OSError, struct.error, json.JSONDecodeError, ConnectionResetError, ValueError) as e:
        print(f"ERROR receiving message: {e}")
        return None
    except Exception as e:
         print(f"UNEXPECTED error receiving message: {e}")
         traceback.print_exc()
         return None

def send_file_content(connection, filepath):
    """Sends file content with size prefix."""
    if not os.path.isfile(filepath):
        print(f"ERROR: File not found for sending: {filepath}")
        try: connection.sendall(struct.pack('>Q', 0))
        except OSError: pass
        return False
    try:
        filesize = os.path.getsize(filepath)
        # TODO: Check against MAX_FILE_SIZE before sending
        if filesize > MAX_FILE_SIZE:
             print(f"ERROR: File size {filesize} exceeds MAX_FILE_SIZE {MAX_FILE_SIZE}")
             log_audit("System", "SEND_FILE_ERR", False, f"File {filepath} too large")
             try: connection.sendall(struct.pack('>Q', 0)) # Send 0 size for error
             except OSError: pass
             return False

        connection.sendall(struct.pack('>Q', filesize)) # Send 8-byte size
        print(f"[Net Send File] Sending: {filepath}, Size: {filesize}")
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk: break
                connection.sendall(chunk)
        print(f"[Net Send File] Finished sending: {filepath}")
        return True
    except (OSError, FileNotFoundError, struct.error) as e:
        print(f"ERROR sending file {filepath}: {e}")
        try: connection.sendall(struct.pack('>Q', 0))
        except OSError: pass
        return False
    except Exception as e:
        print(f"UNEXPECTED error sending file: {e}")
        traceback.print_exc()
        try: connection.sendall(struct.pack('>Q', 0))
        except OSError: pass
        return False


def receive_file_content(connection, save_path):
    """Receives file content with size prefix and saves it."""
    abs_save_path = os.path.abspath(save_path)
    safe_base_path = os.path.abspath(SERVER_FILE_STORAGE_PATH)
    if not abs_save_path.startswith(safe_base_path):
        print(f"SECURITY ERROR: Attempt to save file outside designated storage: {save_path}")
        log_audit("System", "RECV_FILE_ERR", False, f"Path violation: {save_path}")
        # Consume size data to avoid blocking, then fail
        try: connection.recv(8)
        except OSError: pass
        return False, 0

    f = None
    bytes_received = 0
    success = False
    try:
        filesize_data = connection.recv(8)
        if not filesize_data or len(filesize_data) < 8:
             print("ERROR: Failed to receive filesize prefix.")
             return False, 0
        filesize = struct.unpack('>Q', filesize_data)[0]

        # Check against MAX_FILE_SIZE
        if filesize > MAX_FILE_SIZE:
             print(f"ERROR: Incoming file size {filesize} exceeds MAX_FILE_SIZE {MAX_FILE_SIZE}")
             log_audit("System", "RECV_FILE_ERR", False, f"Incoming file too large: {filesize} bytes")
             # TODO: How to tell client? Maybe just close connection or rely on client timeout?
             # We need to consume the data the client might send anyway to prevent blocking
             # This part is tricky without a more robust protocol. For now, just return False.
             return False, 0

        print(f"[Net Recv File] Receiving to: {save_path}, Expected Size: {filesize}")
        ensure_dir_exists(os.path.dirname(save_path))
        f = open(save_path, 'wb')
        while bytes_received < filesize:
            chunk = connection.recv(min(filesize - bytes_received, BUFFER_SIZE))
            if not chunk:
                print("ERROR: Connection closed unexpectedly while receiving file.")
                return False, bytes_received
            f.write(chunk)
            bytes_received += len(chunk)

        print(f"[Net Recv File] Finished receiving: {save_path}, Received: {bytes_received}")
        if bytes_received != filesize:
             print(f"WARNING: Received size {bytes_received} != expected size {filesize}")
             # Treat size mismatch as failure
             return False, bytes_received
        success = True
        return True, bytes_received

    except (OSError, struct.error) as e:
        print(f"ERROR receiving or saving file to {save_path}: {e}")
        return False, bytes_received
    except Exception as e:
        print(f"UNEXPECTED error receiving file: {e}")
        traceback.print_exc()
        return False, bytes_received
    finally:
        if f:
            f.close()
            # Clean up incomplete file if reception failed
            if not success and os.path.exists(save_path):
                if os.path.getsize(save_path) < filesize: # Double check if it's incomplete
                     try:
                         os.remove(save_path)
                         print(f"Removed incomplete file: {save_path}")
                     except OSError as del_err:
                         print(f"ERROR cleaning up incomplete file {save_path}: {del_err}")

# ==================================================
# Section: Request Handlers
# ==================================================

# --- Authentication Helper ---
# TODO: Implement proper session/token based authentication!
# This basic check is insecure and only for the framework structure.
def basic_authenticate(request_data):
    """Checks the insecure shared secret."""
    if request_data.get("shared_secret") == SHARED_SECRET:
        return True
    else:
        log_audit(request_data.get("username", "anonymous"), "AUTH_FAIL", False, "Incorrect shared secret")
        return False

# --- User Handler ---
def handle_register(request_data):
    # No auth needed for register
    username = request_data.get('username')
    password = request_data.get('password')
    response = {"success": False, "message": ""}
    if not username or not password or not isinstance(username, str) or not isinstance(password, str):
        response["message"] = "Username and password required."
        log_audit(username or "N/A", "REGISTER_ATTEMPT", False, response["message"])
        return response
    # TODO: Add password complexity checks

    if not is_safe_filename(username):
        response["message"] = "Username contains invalid characters."
        log_audit(username, "REGISTER_ATTEMPT", False, response["message"])
        return response

    try:
        # --- Secure Password Hashing ---
        salt = os.urandom(16)
        # TODO: Use Argon2, scrypt, or bcrypt instead of PBKDF2 if possible
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
        user_data = {"username": username, "password_hash": hashed_password.hex(), "salt": salt.hex()}

        add_user(username, user_data) # Raises ValueError if exists or IOError on save fail
        response["success"] = True
        response["message"] = "User registered successfully."
        log_audit(username, "REGISTER", True)
    except ValueError as e: # User exists
        response["message"] = str(e)
        log_audit(username, "REGISTER", False, str(e))
    except (IOError, Exception) as e:
        print(f"ERROR during registration for {username}: {e}")
        response["message"] = "Server error during registration."
        log_audit(username, "REGISTER", False, f"Server error: {e}")
    return response

def handle_login(request_data):
    # No auth needed for login itself
    username = request_data.get('username')
    password = request_data.get('password')
    response = {"success": False, "message": ""}
    if not username or not password or not isinstance(username, str) or not isinstance(password, str):
        response["message"] = "Username and password required."
        log_audit(username or "N/A", "LOGIN_ATTEMPT", False, response["message"])
        return response

    user_data = get_user_data(username)
    if not user_data:
        response["message"] = "Invalid username or password."
        log_audit(username, "LOGIN", False, "User not found")
        return response

    stored_hash_hex = user_data.get("password_hash")
    stored_salt_hex = user_data.get("salt")
    if not stored_hash_hex or not stored_salt_hex:
         response["message"] = "Server error: User data incomplete."
         log_audit(username, "LOGIN", False, "Stored hash/salt missing")
         return response

    try:
        salt = bytes.fromhex(stored_salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
        # Verify password
        input_hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
        if hmac.compare_digest(input_hashed_password, stored_hash):
            response["success"] = True
            response["message"] = "Login successful."
            response["username"] = username # Return username on success
            log_audit(username, "LOGIN", True)
            # TODO: Generate and return a secure session token here!
            # response["token"] = generate_token(username)
        else:
            response["message"] = "Invalid username or password."
            log_audit(username, "LOGIN", False, "Password mismatch")
    except (ValueError, TypeError) as e:
         response["message"] = "Server error during login validation."
         log_audit(username, "LOGIN", False, f"Hash/salt format error: {e}")
    return response

# --- File Handler ---
def handle_upload_request(request_data):
    """Handles the first part of upload: checking permissions and readiness."""
    # TODO: Replace basic_authenticate with token validation!
    if not basic_authenticate(request_data): return {"success": False, "message": "Authentication failed."}

    username = request_data.get("username") # TODO: Get from token
    original_filename = request_data.get("filename")
    response = {"success": False, "message": ""}

    if not username: # Should not happen if auth passed
        response["message"] = "Internal error: Username missing after auth."
        return response

    if not original_filename or not isinstance(original_filename, str):
        response["message"] = "Filename is required."
        log_audit(username, "UPLOAD_REQUEST", False, response["message"])
        return response

    if not is_safe_filename(original_filename):
        response["message"] = "Invalid or unsafe filename provided."
        log_audit(username, "UPLOAD_REQUEST", False, response["message"])
        return response

    # Generate UUID for internal storage
    file_uuid = str(uuid.uuid4())
    save_path = os.path.join(SERVER_FILE_STORAGE_PATH, f"{file_uuid}.enc")

    # Check for potential UUID collision (extremely unlikely, but good practice)
    if os.path.exists(save_path) or os.path.exists(save_path[:-4] + ".meta"):
         response["message"] = "Internal server error (UUID collision). Please try again."
         log_audit(username, "UPLOAD_REQUEST", False, "UUID collision")
         return response

    response["success"] = True
    response["message"] = "Server ready to receive file."
    response["file_uuid"] = file_uuid # Send back UUID for finalizing
    log_audit(username, "UPLOAD_REQUEST", True, f"File: {original_filename}, UUID: {file_uuid}")
    # The caller (handle_connection) will now expect file data
    return response

def finalize_upload(username, original_filename, file_uuid, success, filesize):
    """Called after file transfer attempt to save metadata."""
    response = {"success": False, "message": ""}
    if success:
        timestamp = datetime.datetime.now().isoformat()
        metadata = {
            "original_filename": original_filename,
            "owner_username": username,
            "filesize": filesize,
            "upload_timestamp": timestamp,
            "shared_with": []
            # TODO: Consider adding a hash of the *encrypted* content for integrity?
        }
        if save_file_metadata(file_uuid, metadata):
             response["success"] = True
             response["message"] = f"File '{original_filename}' uploaded successfully."
             log_audit(username, "UPLOAD_COMPLETE", True, f"File: {original_filename}, UUID: {file_uuid}, Size: {filesize}")
        else:
             response["message"] = "Failed to save file metadata after upload."
             log_audit(username, "UPLOAD_COMPLETE", False, f"Metadata save failed for UUID: {file_uuid}")
             # Critical: If metadata fails, try to clean up the uploaded .enc file
             print(f"CRITICAL: Metadata save failed for {file_uuid}. Attempting to delete orphaned content file.")
             delete_file_data(file_uuid) # Attempt cleanup
    else:
        # File transfer failed, no metadata to save. Log already happened in receive_file.
        response["message"] = "File upload failed during transfer."
        # Log might have happened in receive_file_content failure path
        # log_audit(username, "UPLOAD_COMPLETE", False, f"File transfer failed for {original_filename}")
        # Ensure cleanup happened in receive_file_content's finally block
    return response

def handle_list_files(request_data):
    """Handles listing user's accessible files."""
    # TODO: Replace basic_authenticate with token validation!
    if not basic_authenticate(request_data): return {"success": False, "message": "Authentication failed."}
    username = request_data.get("username") # TODO: Get from token
    response = {"success": False, "message": "", "files": []}
    if not username: return {"success": False, "message": "Internal error: Username missing."}

    all_files_meta = list_all_files_metadata()
    user_files = []
    for meta in all_files_meta:
        is_owner = meta.get("owner_username") == username
        is_shared_with = username in meta.get("shared_with", [])
        if is_owner or is_shared_with:
            # Select info to send back
            file_info = {
                "filename": meta.get("original_filename", "N/A"),
                "uuid": meta.get("uuid", "N/A"),
                "size": meta.get("filesize", -1),
                "upload_date": meta.get("upload_timestamp", "N/A"),
                "is_owner": is_owner
            }
            user_files.append(file_info)

    response["success"] = True
    response["files"] = user_files
    log_audit(username, "LIST_FILES", True, f"Found {len(user_files)} files")
    return response

def handle_download_request(request_data):
    """Handles the first part of download: checking permissions."""
    # TODO: Replace basic_authenticate with token validation!
    if not basic_authenticate(request_data): return {"success": False, "message": "Authentication failed."}
    username = request_data.get("username") # TODO: Get from token
    file_uuid = request_data.get("file_uuid")
    response = {"success": False, "message": ""}
    if not username: return {"success": False, "message": "Internal error: Username missing."}

    if not file_uuid or not isinstance(file_uuid, str):
        response["message"] = "File UUID is required."
        log_audit(username, "DOWNLOAD_REQUEST", False, response["message"])
        return response

    metadata = get_file_metadata(file_uuid)
    if not metadata:
        response["message"] = "File not found."
        log_audit(username, "DOWNLOAD_REQUEST", False, f"UUID not found: {file_uuid}")
        return response

    # --- Permission Check ---
    is_owner = metadata.get("owner_username") == username
    is_shared_with = username in metadata.get("shared_with", [])
    if not (is_owner or is_shared_with):
        response["message"] = "Permission denied."
        log_audit(username, "DOWNLOAD_REQUEST", False, f"Permission denied for UUID: {file_uuid}")
        return response

    # Check if content file actually exists
    file_path = get_file_content_path(file_uuid)
    if not file_path:
        response["message"] = "File content not found on server (metadata exists). Possible server issue."
        log_audit(username, "DOWNLOAD_REQUEST", False, f"File content missing for UUID: {file_uuid}")
        # TODO: Maybe try to clean up the orphaned metadata? delete_file_data(file_uuid)?
        return response

    response["success"] = True
    response["message"] = "Server ready to send file."
    response["filename"] = metadata.get("original_filename", "file") # Provide original name
    log_audit(username, "DOWNLOAD_REQUEST", True, f"UUID: {file_uuid}, File: {metadata.get('original_filename')}")
    # The caller (handle_connection) will now expect to send the file
    return response

def handle_delete(request_data):
    """Handles deleting a file."""
    # TODO: Replace basic_authenticate with token validation!
    if not basic_authenticate(request_data): return {"success": False, "message": "Authentication failed."}
    username = request_data.get("username") # TODO: Get from token
    file_uuid = request_data.get("file_uuid")
    response = {"success": False, "message": ""}
    if not username: return {"success": False, "message": "Internal error: Username missing."}

    if not file_uuid or not isinstance(file_uuid, str):
        response["message"] = "File UUID is required."
        log_audit(username, "DELETE_ATTEMPT", False, response["message"])
        return response

    metadata = get_file_metadata(file_uuid)
    if not metadata:
        response["success"] = True # Deleting non-existent file is often idempotent
        response["message"] = "File not found or already deleted."
        log_audit(username, "DELETE", True, f"File not found (UUID: {file_uuid}), treated as success.")
        return response

    # --- Permission Check: Only owner can delete ---
    if metadata.get("owner_username") != username:
        response["message"] = "Permission denied. Only the owner can delete the file."
        log_audit(username, "DELETE", False, f"Permission denied for UUID: {file_uuid}")
        return response

    original_filename = metadata.get("original_filename", "N/A")
    if delete_file_data(file_uuid):
        response["success"] = True
        response["message"] = f"File '{original_filename}' deleted successfully."
        log_audit(username, "DELETE", True, f"Deleted UUID: {file_uuid}, File: {original_filename}")
    else:
        response["message"] = "Failed to delete file due to server error."
        log_audit(username, "DELETE", False, f"Error deleting UUID: {file_uuid}")
    return response

# --- Share Handler ---
def handle_share(request_data):
    """Handles sharing a file with another user."""
    # TODO: Replace basic_authenticate with token validation!
    if not basic_authenticate(request_data): return {"success": False, "message": "Authentication failed."}
    owner_username = request_data.get("username") # TODO: Get from token
    file_uuid = request_data.get("file_uuid")
    share_with_username = request_data.get("share_with_username")
    response = {"success": False, "message": ""}
    if not owner_username: return {"success": False, "message": "Internal error: Username missing."}

    if not file_uuid or not isinstance(file_uuid, str) or \
       not share_with_username or not isinstance(share_with_username, str):
        response["message"] = "File UUID and username to share with are required."
        log_audit(owner_username, "SHARE_ATTEMPT", False, response["message"])
        return response

    if owner_username == share_with_username:
        response["message"] = "You cannot share a file with yourself."
        log_audit(owner_username, "SHARE", False, response["message"])
        return response

    # Check target user exists
    if not user_exists(share_with_username):
        response["message"] = f"User '{share_with_username}' to share with does not exist."
        log_audit(owner_username, "SHARE", False, response["message"])
        return response

    metadata = get_file_metadata(file_uuid)
    if not metadata:
        response["message"] = "File not found."
        log_audit(owner_username, "SHARE", False, f"File not found: {file_uuid}")
        return response

    # --- Permission Check: Only owner can share ---
    if metadata.get("owner_username") != owner_username:
        response["message"] = "Permission denied. Only the owner can share the file."
        log_audit(owner_username, "SHARE", False, f"Permission denied for UUID: {file_uuid}")
        return response

    shared_with_list = metadata.get("shared_with", [])
    if share_with_username not in shared_with_list:
        shared_with_list.append(share_with_username)
        metadata["shared_with"] = shared_with_list

        # Save updated metadata
        if save_file_metadata(file_uuid, metadata):
            response["success"] = True
            response["message"] = f"File shared with '{share_with_username}' successfully."
            log_audit(owner_username, "SHARE", True, f"Shared UUID {file_uuid} with {share_with_username}")
        else:
            # Attempt to revert change in memory? No, just report error.
            response["message"] = "Failed to update file metadata for sharing due to server error."
            log_audit(owner_username, "SHARE", False, f"Failed to save metadata for UUID: {file_uuid}")
    else:
        response["success"] = True # Already shared is ok
        response["message"] = f"File is already shared with '{share_with_username}'."
        log_audit(owner_username, "SHARE", True, f"Already shared UUID {file_uuid} with {share_with_username}")

    return response

# TODO: Implement handle_unshare

# ==================================================
# Section: Main Connection Handler & Server Logic
# ==================================================

class SimpleTCPHandler(socketserver.BaseRequestHandler):
    """Handles incoming connections sequentially."""

    def handle(self):
        client_address = self.client_address
        print(f"Connection established from {client_address}")
        log_audit(f"System ({client_address[0]})", "CONNECT", True)

        try:
            # Loop to handle multiple requests per connection
            while True:
                # 1. Receive JSON request
                request_data = receive_message(self.request)
                if not request_data:
                    print(f"Client {client_address} disconnected or sent invalid message.")
                    break # Exit loop on disconnect or error

                action = request_data.get("action")
                print(f"[Handler] Received action: {action} from {client_address}")

                # --- Default response ---
                response = {"success": False, "message": "Invalid action or server error."}
                file_path_to_send = None
                expecting_file_upload = False
                upload_details = {} # Store details needed after upload

                # 2. Route action to appropriate handler
                # Note: We pass request_data to handlers. They should perform auth checks.
                if action == "register":
                    response = handle_register(request_data)
                elif action == "login":
                    response = handle_login(request_data)
                    # TODO: Handle token from response if login succeeds
                elif action == "upload_request":
                    response = handle_upload_request(request_data)
                    if response.get("success"):
                        expecting_file_upload = True
                        upload_details = { # Store needed info
                           "username": request_data.get("username"), # TODO: Get from token
                           "original_filename": request_data.get("filename"),
                           "file_uuid": response.get("file_uuid")
                        }
                elif action == "list_files":
                     response = handle_list_files(request_data)
                elif action == "download_request":
                     response = handle_download_request(request_data)
                     if response.get("success"):
                         file_path_to_send = get_file_content_path(request_data.get("file_uuid"))
                         if not file_path_to_send: # Double check content exists
                              print(f"ERROR: Content path not found for UUID {request_data.get('file_uuid')} after permission check!")
                              response = {"success": False, "message": "Internal server error: File content missing."}
                              log_audit(request_data.get("username"), "DOWNLOAD_FAIL", False, f"Content missing for {request_data.get('file_uuid')}")
                elif action == "delete":
                     response = handle_delete(request_data)
                elif action == "share":
                     response = handle_share(request_data)
                # TODO: Add 'unshare', 'reset_password' etc.
                else:
                    log_audit(request_data.get("username", "anonymous"), "INVALID_ACTION", False, f"Action: {action}")
                    # Keep default error response

                # 3. Send JSON response back to client
                if not send_message(self.request, response):
                     print(f"Failed to send response for action '{action}' to {client_address}. Closing connection.")
                     break # Exit loop if response fails

                # 4. Handle file transfer if required by the action
                if expecting_file_upload:
                    if response.get("success"): # Double check server is ready
                        save_path = os.path.join(SERVER_FILE_STORAGE_PATH, f"{upload_details['file_uuid']}.enc")
                        print(f"[Handler] Expecting file upload to {save_path}...")
                        success, bytes_received = receive_file_content(self.request, save_path)
                        # Finalize (save metadata) regardless of transfer success/failure
                        # TODO: Pass actual username securely
                        final_response = finalize_upload(
                            upload_details["username"],
                            upload_details["original_filename"],
                            upload_details["file_uuid"],
                            success,
                            bytes_received # Pass received bytes as filesize
                        )
                        print(f"[Handler] Upload finalized: {final_response}")
                        # TODO: Protocol currently doesn't send this finalize response back.
                    else:
                        # Server wasn't ready (upload_request failed), client shouldn't send file.
                        print(f"[Handler] Upload request failed, not expecting file from {client_address}")

                elif file_path_to_send:
                    if response.get("success"): # Double check permission was granted
                        print(f"[Handler] Sending file {file_path_to_send} to {client_address}...")
                        send_success = send_file_content(self.request, file_path_to_send)
                        if send_success:
                             log_audit(request_data.get("username"), "DOWNLOAD_COMPLETE", True, f"File: {response.get('filename')}")
                        else:
                             log_audit(request_data.get("username"), "DOWNLOAD_FAIL", False, f"Send error for file: {response.get('filename')}")
                    else:
                        # Download request failed, client shouldn't expect file.
                         print(f"[Handler] Download request failed, not sending file to {client_address}")

                # If action was 'logout' or similar that should end session, break loop here?
                # if action == "logout": break

        except ConnectionResetError:
            print(f"Connection reset by peer {client_address}")
            log_audit(f"System ({client_address[0]})", "DISCONNECT", True, "Connection reset")
        except BrokenPipeError:
            print(f"Broken pipe with client {client_address}")
            log_audit(f"System ({client_address[0]})", "DISCONNECT", True, "Broken pipe")
        except Exception as e:
            print(f"!!! UNEXPECTED error handling client {client_address}: {e}")
            traceback.print_exc()
            log_audit(f"System ({client_address[0]})", "HANDLER_ERROR", False, str(e))
        finally:
            print(f"Connection closed from {client_address}")
            log_audit(f"System ({client_address[0]})", "DISCONNECT", True)
            # Connection is automatically closed by socketserver

# ==================================================
# Section: Server Startup
# ==================================================
def run_server():
    """Starts the TCP server."""
    initialize_storage() # Ensure directories exist before starting

    # Using TCPServer for sequential handling (satisfies "no concurrency" assumption)
    server = socketserver.TCPServer((SERVER_HOST, SERVER_PORT), SimpleTCPHandler)
    print(f"Server starting on {SERVER_HOST}:{SERVER_PORT}...")
    print("Mode: Single-threaded, sequential request handling.")
    print(f"Metadata: {os.path.abspath(SERVER_METADATA_PATH)}")
    print(f"Storage:  {os.path.abspath(SERVER_FILE_STORAGE_PATH)}")
    print("Waiting for connections...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCtrl+C received. Server shutting down.")
    except Exception as e:
        print(f"\n!!! Server error: {e}")
        traceback.print_exc()
    finally:
        print("Closing server socket.")
        server.shutdown() # Stop serve_forever loop
        server.server_close() # Release port
        log_audit("System", "SHUTDOWN", True)
        print("Server stopped.")

if __name__ == '__main__':
    run_server()