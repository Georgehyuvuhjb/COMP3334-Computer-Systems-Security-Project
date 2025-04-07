# client.py
import socket
import json
import struct
import os
import sys
import getpass # For hidden password input
import traceback

import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



# ==================================================
# Section: Configuration (原本在 config_client.py)
# ==================================================
SERVER_HOST = 'localhost' # 或伺服器的 IP 地址
SERVER_PORT = 9999
BUFFER_SIZE = 4096
# TODO: CHANGE THIS! Should match the server's secret and be handled securely.
SHARED_SECRET = "insecure_default_secret"
LOCAL_KEY_FILE = "client_secret_key.key" # TODO: Extremely insecure way to store key!

# ==================================================
# Section: File Handling (原本在 file_handler_client.py)
# ==================================================
def read_file_chunked(filepath, chunk_size):
    """Reads file in chunks (generator)."""
    try:
        # 檢查文件是否存在且可讀
        if not os.path.isfile(filepath):
             print(f"ERROR: File not found or is not a file: {filepath}")
             return None # Return None instead of yielding to indicate failure early
        # 檢查文件大小 (可選，防止讀取超大文件?)
        # filesize = os.path.getsize(filepath)
        # if filesize > SOME_MAX_LIMIT:
        #    print(f"ERROR: File size exceeds limit: {filepath}")
        #    return None

        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break # End of file
                yield chunk
    except FileNotFoundError:
        print(f"ERROR: File not found during read: {filepath}")
        # Already checked, but handle race condition perhaps
        return None
    except IOError as e:
        print(f"ERROR reading file {filepath}: {e}")
        return None
    except Exception as e:
        print(f"UNEXPECTED error reading file {filepath}: {e}")
        traceback.print_exc()
        return None # Indicate failure

def write_file_chunked(filepath, data_chunks_generator):
    """Writes data chunks from a generator to a file."""
    f = None
    success = False
    try:
        # Ensure target directory exists
        dir_path = os.path.dirname(filepath)
        if dir_path and not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
                print(f"Created directory: {dir_path}")
            except OSError as e:
                 print(f"ERROR creating directory {dir_path}: {e}")
                 return False # Cannot proceed if dir creation fails

        print(f"Writing to file: {filepath}")
        with open(filepath, 'wb') as f:
            chunk_index = 0
            for chunk in data_chunks_generator:
                if chunk is None: # Sentinel value indicating upstream error (e.g., network, decrypt)
                    print("ERROR: Received error signal (None chunk) while writing file. Aborting.")
                    return False # Indicate failure
                f.write(chunk)
                # print(f"Wrote chunk {chunk_index}") # Debug
                chunk_index += 1
        success = True
        print(f"Finished writing file: {filepath}")
        return True
    except IOError as e:
        print(f"ERROR writing file {filepath}: {e}")
        return False
    except Exception as e:
        print(f"UNEXPECTED error writing file {filepath}: {e}")
        traceback.print_exc()
        return False
    finally:
        # Clean up incomplete file if writing failed
        if not success and os.path.exists(filepath):
             print(f"Attempting to clean up incomplete file: {filepath}")
             try:
                 # Check if the file was actually opened before trying to remove
                 # We might fail before f = open(...) succeeds
                 if 'f' in locals() and f is not None and not f.closed:
                      f.close() # Ensure file is closed before deleting
                 os.remove(filepath)
                 print(f"Removed incomplete file: {filepath}")
             except OSError as del_err:
                 print(f"ERROR cleaning up incomplete file {filepath}: {del_err}")


# ==================================================
# Section: Cryptography (Placeholder - 原本在 crypto_client.py)
# TODO: IMPLEMENT REAL CRYPTOGRAPHY USING 'cryptography' LIBRARY
# ==================================================
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.exceptions import InvalidTag

def load_or_generate_key():
    """
    Loads or generates a key.
    TODO: THIS IS EXTREMELY INSECURE! Implement secure key derivation/storage.
    """
    # Placeholder implementation
    global SECRET_KEY
    key_len = 32 # For AES-256
    if os.path.exists(LOCAL_KEY_FILE):
        try:
            with open(LOCAL_KEY_FILE, 'rb') as f:
                key = f.read()
            if len(key) == key_len:
                print("Loaded existing key (INSECURE STORAGE).")
                SECRET_KEY = key
                return
            else:
                 print(f"Warning: Existing key file '{LOCAL_KEY_FILE}' has incorrect length. Generating new key.")
        except Exception as e:
             print(f"Warning: Could not load key from '{LOCAL_KEY_FILE}': {e}. Generating new key.")

    print(f"Generating new key and saving to '{LOCAL_KEY_FILE}' (INSECURE STORAGE).")
    # TODO: Ensure proper file permissions if using file storage (chmod 600)
    key = os.urandom(key_len)
    try:
        with open(LOCAL_KEY_FILE, 'wb') as f:
            f.write(key)
        SECRET_KEY = key
    except Exception as e:
         print(f"FATAL: Could not save generated key to '{LOCAL_KEY_FILE}': {e}")
         SECRET_KEY = None # Indicate key failure

SECRET_KEY = None
load_or_generate_key() # Load or generate key on script start

# def encrypt_chunk(chunk):
#     """Encrypts a chunk of data. Placeholder."""
#     if not SECRET_KEY: raise ValueError("Encryption key not available.")
#     if chunk is None: return None
#     # TODO: Implement actual AES (GCM recommended) encryption here.
#     # Remember IV handling, potential padding, and GCM tags.
#     # print("[DEBUG Encrypt] Plaintext chunk size:", len(chunk))
#     encrypted_chunk = chunk # Placeholder: No encryption
#     # print("[DEBUG Encrypt] Ciphertext chunk size:", len(encrypted_chunk))
#     return encrypted_chunk

# def decrypt_chunk(encrypted_chunk):
#     """Decrypts a chunk of data. Placeholder."""
#     if not SECRET_KEY: raise ValueError("Decryption key not available.")
#     if encrypted_chunk is None: return None
#     # TODO: Implement actual AES (GCM recommended) decryption here.
#     # Remember IV handling, GCM tag verification, padding removal.
#     # print("[DEBUG Decrypt] Ciphertext chunk size:", len(encrypted_chunk))
#     decrypted_chunk = encrypted_chunk # Placeholder: No decryption
#     # print("[DEBUG Decrypt] Plaintext chunk size:", len(decrypted_chunk))
#     return decrypted_chunk

def encrypt_chunk(chunk):
    """
    Encrypts a chunk of data using AES-GCM.
    Returns: a byte string containing IV + ciphertext + tag
    """
    if not SECRET_KEY: raise ValueError("Encryption key not available.")
    if chunk is None: return None
    
    try:
        # Generate a random 96-bit IV (12 bytes) for each chunk
        # Using a unique IV for each chunk is critical for security
        iv = os.urandom(12)
        
        # Create an AES-GCM cipher instance
        aesgcm = AESGCM(SECRET_KEY)
        
        # Encrypt the chunk - GCM automatically includes authentication tag
        # None parameter is for Associated Data - not using any here
        ciphertext = aesgcm.encrypt(iv, chunk, None)
        
        # Return IV + ciphertext (tag is included in ciphertext by the API)
        encrypted_chunk = iv + ciphertext
        
        # Debug info if needed
        # print(f"[DEBUG Encrypt] Plaintext size: {len(chunk)}, Ciphertext size: {len(encrypted_chunk)}")
        
        return encrypted_chunk
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_chunk(encrypted_chunk):
    """
    Decrypts a chunk of data using AES-GCM.
    Expects: IV (12 bytes) + ciphertext + tag
    """
    if not SECRET_KEY: raise ValueError("Decryption key not available.")
    if encrypted_chunk is None: return None
    
    try:
        # Ensure we have at least an IV
        if len(encrypted_chunk) <= 12:
            print("ERROR: Encrypted chunk too small, missing IV or content")
            return None
            
        # Extract IV and ciphertext
        iv = encrypted_chunk[:12]
        ciphertext = encrypted_chunk[12:]
        
        # Create an AES-GCM cipher instance
        aesgcm = AESGCM(SECRET_KEY)
        
        # Decrypt and verify authentication
        # If authentication fails (tampered data), this will raise an exception
        decrypted_chunk = aesgcm.decrypt(iv, ciphertext, None)
        
        # Debug info if needed
        # print(f"[DEBUG Decrypt] Ciphertext size: {len(encrypted_chunk)}, Plaintext size: {len(decrypted_chunk)}")
        
        return decrypted_chunk
    except Exception as e:
        print(f"Decryption error (possibly tampered data): {e}")
        return None
    
def encrypt_file_stream(filepath, chunk_size):
    """Generator that reads, encrypts, and yields file chunks."""
    if not SECRET_KEY:
        print("ERROR: Encryption key is not available.")
        yield None # Signal error
        return

    file_reader = read_file_chunked(filepath, chunk_size)
    if file_reader is None:
         yield None # Signal error from file reading
         return

    print(f"Starting encryption stream for {filepath}")
    chunk_index = 0
    try:
        for plain_chunk in file_reader:
            if plain_chunk is None: # Error reading chunk
                 yield None
                 return # Stop generation
            # print(f"[Encrypt Stream] Read chunk {chunk_index}, size {len(plain_chunk)}")
            encrypted_chunk = encrypt_chunk(plain_chunk)
            if encrypted_chunk is None: # Encryption error
                 print(f"ERROR: Encryption failed for chunk {chunk_index}")
                 yield None
                 return # Stop generation
            # print(f"[Encrypt Stream] Yielding encrypted chunk {chunk_index}, size {len(encrypted_chunk)}")
            yield encrypted_chunk
            chunk_index += 1
        print(f"Finished encryption stream for {filepath}")
        # TODO: Handle final block/tag for certain modes if necessary
    except Exception as e:
        print(f"UNEXPECTED error during encryption stream: {e}")
        traceback.print_exc()
        yield None # Signal error


def decrypt_file_stream(encrypted_chunks_iterator):
    """Generator that receives encrypted chunks, decrypts, and yields plaintext."""
    if not SECRET_KEY:
        print("ERROR: Decryption key is not available.")
        yield None # Signal error
        return

    print("Starting decryption stream...")
    chunk_index = 0
    try:
        for encrypted_chunk in encrypted_chunks_iterator:
            if encrypted_chunk is None: # Network error signal
                yield None
                return # Stop generation
            # print(f"[Decrypt Stream] Received encrypted chunk {chunk_index}, size {len(encrypted_chunk)}")
            decrypted_chunk = decrypt_chunk(encrypted_chunk)
            if decrypted_chunk is None: # Decryption error (e.g., bad tag)
                 print(f"ERROR: Decryption failed for chunk {chunk_index}")
                 yield None
                 return # Stop generation
            # print(f"[Decrypt Stream] Yielding decrypted chunk {chunk_index}, size {len(decrypted_chunk)}")
            yield decrypted_chunk
            chunk_index += 1
        print("Finished decryption stream.")
    except Exception as e:
        print(f"UNEXPECTED error during decryption stream: {e}")
        traceback.print_exc()
        yield None # Signal error

# ==================================================
# Section: Network Communication (原本在 network_client.py)
# ==================================================
current_connection = None # Global connection state

def connect_to_server():
    """Establishes connection to the server."""
    global current_connection
    if current_connection:
        # print("Already connected.")
        return current_connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TODO: Add timeout? sock.settimeout(10)
        sock.connect((SERVER_HOST, SERVER_PORT))
        current_connection = sock
        print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")
        return sock
    except socket.error as e:
        print(f"ERROR connecting to server: {e}")
        current_connection = None
        return None
    except Exception as e:
        print(f"UNEXPECTED error connecting to server: {e}")
        current_connection = None
        return None


def disconnect_from_server():
    """Closes the connection."""
    global current_connection, logged_in_user # Reset logged_in_user on disconnect
    if current_connection:
        try:
            current_connection.close()
            print("Disconnected from server.")
        except Exception as e:
            print(f"Error closing connection: {e}")
        finally:
            current_connection = None
            logged_in_user = None # Clear logged in state


def send_request(sock, request_data):
    """Sends a JSON request with length prefix and shared secret."""
    if not sock:
        print("ERROR: Not connected to server.")
        return False
    try:
        # Automatically add the insecure shared secret for basic auth
        request_data['shared_secret'] = SHARED_SECRET
        json_message = json.dumps(request_data).encode('utf-8')
        message_len = len(json_message)
        # TODO: Check message size against a reasonable limit?
        len_prefix = struct.pack('>I', message_len)
        sock.sendall(len_prefix)
        sock.sendall(json_message)
        # print(f"[Net Send] {request_data}") # Debug
        return True
    except (socket.error, json.JSONDecodeError, TypeError, struct.error) as e:
        print(f"ERROR sending request: {e}")
        disconnect_from_server() # Disconnect on send error
        return False
    except Exception as e:
         print(f"UNEXPECTED error sending request: {e}")
         traceback.print_exc()
         disconnect_from_server()
         return False

def receive_response(sock):
    """Receives a JSON response with length prefix."""
    if not sock:
        print("ERROR: Not connected to server.")
        return None
    try:
        len_prefix_data = sock.recv(4)
        if not len_prefix_data or len(len_prefix_data) < 4:
             print("Connection closed by server or incomplete length prefix.")
             disconnect_from_server()
             return None
        message_len = struct.unpack('>I', len_prefix_data)[0]
        # TODO: Check message_len against a reasonable limit

        received_data = b''
        while len(received_data) < message_len:
            chunk = sock.recv(min(message_len - len(received_data), BUFFER_SIZE))
            if not chunk:
                print("Connection closed by server while receiving response body.")
                disconnect_from_server()
                return None
            received_data += chunk

        response = json.loads(received_data.decode('utf-8'))
        # print(f"[Net Recv] {response}") # Debug
        return response
    except (socket.error, struct.error, json.JSONDecodeError, ConnectionResetError, ValueError) as e:
        print(f"ERROR receiving response: {e}")
        disconnect_from_server() # Disconnect on receive error
        return None
    except Exception as e:
         print(f"UNEXPECTED error receiving response: {e}")
         traceback.print_exc()
         disconnect_from_server()
         return None

def send_file_stream(sock, file_stream_generator):
    """Sends a stream of (encrypted) file chunks."""
    if not sock: return False, 0
    total_bytes_sent = 0
    success = False
    try:
        # TODO: Protocol requires sending file size *before* content.
        # This is hard with encryption as size changes.
        # Option 1: Encrypt entire file to temp file, get size, send temp file. (Inefficient for large files)
        # Option 2: Negotiate - send data chunked, use special end-of-file marker. (Requires protocol change)
        # Option 3: Server calculates size after receiving. (Current server implies size is sent first)
        # --- WORKAROUND: Send ORIGINAL filesize first (server needs to know this isn't encrypted size) ---
        # --- This is conceptually flawed if the server strictly expects encrypted size ---
        # --- Let's assume for now the server handles the size received just before data ---
        # --- We need to calculate the size *before* iterating the generator! ---

        # --- TEMPORARY FLAWED APPROACH: We don't know the encrypted size beforehand! ---
        # --- We will rely on the server's receive_file_content reading the size first ---
        # --- Let's simulate sending a placeholder size first (THIS NEEDS FIXING) ---
        # sock.sendall(struct.pack('>Q', 0)) # Placeholder size 0 ?? Extremely problematic

        print("Starting file stream send...")
        chunk_index=0
        for chunk in file_stream_generator:
            if chunk is None: # Upstream error (read/encrypt)
                print("ERROR: Aborting file send due to error in chunk generator.")
                # How to signal error to server? Closing connection might be only way.
                return False, total_bytes_sent
            # print(f"[Send Stream] Sending chunk {chunk_index}, size {len(chunk)}")
            sock.sendall(chunk)
            total_bytes_sent += len(chunk)
            chunk_index += 1
        print(f"Finished sending file stream, total bytes: {total_bytes_sent}")
        success = True
        return True, total_bytes_sent
    except socket.error as e:
        print(f"ERROR sending file stream: {e}")
        disconnect_from_server()
        return False, total_bytes_sent
    except Exception as e:
         print(f"UNEXPECTED error sending file stream: {e}")
         traceback.print_exc()
         disconnect_from_server()
         return False, total_bytes_sent


def receive_file_stream(sock):
    """Generator receiving a stream of (encrypted) file chunks."""
    if not sock: yield None; return
    bytes_received = 0
    try:
        # 1. Receive expected filesize (sent by server)
        filesize_data = sock.recv(8)
        if not filesize_data or len(filesize_data) < 8:
            print("ERROR: Failed to receive filesize prefix from server.")
            yield None; return
        filesize = struct.unpack('>Q', filesize_data)[0]

        if filesize == 0:
            print("Received filesize 0 from server. Assuming server-side error or empty file.")
            # Don't yield anything further if size is 0 indicating error
            return

        print(f"Expecting file of size: {filesize} bytes from server.")

        # 2. Receive content chunks
        while bytes_received < filesize:
            bytes_to_receive = min(filesize - bytes_received, BUFFER_SIZE)
            chunk = sock.recv(bytes_to_receive)
            if not chunk:
                print("ERROR: Connection closed by server unexpectedly while receiving file stream.")
                yield None; return # Signal error
            # print(f"[Recv Stream] Received chunk size {len(chunk)}") # Debug
            yield chunk
            bytes_received += len(chunk)

        print(f"Finished receiving file stream, total bytes: {bytes_received}")
        if bytes_received != filesize:
            print(f"WARNING: Received bytes {bytes_received} != expected {filesize}. Data may be incomplete.")
            # Yield None to signal potential incompletion? Or let downstream handle?
            yield None # Signal potential error

    except (socket.error, struct.error, ConnectionResetError) as e:
        print(f"ERROR receiving file stream: {e}")
        disconnect_from_server()
        yield None # Signal error
    except Exception as e:
         print(f"UNEXPECTED error receiving file stream: {e}")
         traceback.print_exc()
         disconnect_from_server()
         yield None # Signal error


# ==================================================
# Section: Client Logic (原本在 client_logic.py)
# ==================================================
logged_in_user = None # Global state for logged in user
# TODO: Replace username state with a session token received from server

def do_register(username, password):
    """Handles registration action."""
    if not connect_to_server(): return False
    request = {"action": "register", "username": username, "password": password}
    success = False
    if send_request(current_connection, request):
        response = receive_response(current_connection)
        if response:
            print(f"Server: {response.get('message', 'No message.')}")
            success = response.get('success', False)
    # Close connection after registration attempt
    disconnect_from_server()
    return success

def do_login(username, password):
    """Handles login action."""
    global logged_in_user
    if not connect_to_server(): return False
    request = {"action": "login", "username": username, "password": password}
    success = False
    if send_request(current_connection, request):
        response = receive_response(current_connection)
        if response:
            print(f"Server: {response.get('message', 'No message.')}")
            success = response.get('success', False)
            if success:
                logged_in_user = response.get('username') # Store username
                print(f"Successfully logged in as {logged_in_user}.")
                # TODO: Store received session token here!
            else:
                disconnect_from_server() # Disconnect on failed login
        else:
            # receive_response handles disconnect on error
            pass
    return success

def do_list_files():
    """Handles listing files."""
    if not logged_in_user or not current_connection:
        print("Please log in first.")
        return None
    request = {"action": "list_files", "username": logged_in_user} # TODO: Send token instead
    files = None
    if send_request(current_connection, request):
        response = receive_response(current_connection)
        if response and response.get('success'):
            files = response.get('files', [])
            print("\n--- Your Files ---")
            if not files:
                print("(No files found)")
            else:
                for f in files:
                    owner_str = "(Owner)" if f.get('is_owner') else "(Shared)"
                    print(f"- Name: {f.get('filename', 'N/A'):<30} {owner_str:<10} "
                          f"Size: {f.get('size', -1):<10} UUID: {f.get('uuid', 'N/A')}")
            print("------------------")
        elif response:
            print(f"Server error: {response.get('message', 'Unknown error')}")
        # else: receive_response handles errors/disconnect
    return files

# def do_upload_file(filepath):
#     """Handles uploading a file."""
#     if not logged_in_user or not current_connection:
#         print("Please log in first.")
#         return False
#     if not os.path.exists(filepath) or not os.path.isfile(filepath):
#         print(f"ERROR: File not found or is not a file: {filepath}")
#         return False

#     filename = os.path.basename(filepath)
#     print(f"Preparing to upload '{filename}'...")

#     # 1. Send upload request
#     request = {"action": "upload_request", "username": logged_in_user, "filename": filename} # TODO: Send token
#     if not send_request(current_connection, request): return False

#     response = receive_response(current_connection)
#     if not response or not response.get("success"):
#         print(f"Server rejected upload: {response.get('message', 'Unknown error') if response else 'Connection error'}")
#         return False

#     print(f"Server ready. Encrypting and uploading...")

#     # 2. Get encrypted stream generator
#     # TODO: Adjust chunk size based on crypto overhead if necessary
#     encrypted_stream_gen = encrypt_file_stream(filepath, BUFFER_SIZE - 64) # Leave some room

#     if encrypted_stream_gen is None:
#          print("ERROR: Failed to initialize encryption stream.")
#          # TODO: Need to inform server upload is cancelled? Current protocol doesn't support this well. Maybe just disconnect.
#          disconnect_from_server()
#          return False

#     # 3. Send the file stream
#     # TODO: FIX THE FILESIZE SENDING PROBLEM. The current network code might not work correctly
#     # because send_file_stream doesn't send the size first, but receive_file_content expects it.
#     # This needs a protocol adjustment or client-side size calculation of encrypted data.
#     print("WARNING: Filesize handling in current protocol for upload is flawed!")

#     # --- Temporary measure: Let's try sending original filesize ---
#     # --- Server's receive_file_content MUST be aware this is original size ---
#     original_filesize = os.path.getsize(filepath)
#     try:
#          print(f"Sending original filesize: {original_filesize}")
#          current_connection.sendall(struct.pack('>Q', original_filesize))
#     except socket.error as e:
#          print(f"ERROR sending filesize: {e}")
#          disconnect_from_server()
#          return False
#     # --- End temporary measure ---

#     success, bytes_sent = send_file_stream(current_connection, encrypted_stream_gen)

#     if success:
#         print(f"File stream sent ({bytes_sent} encrypted bytes). Waiting for server finalization (if any)...")
#         # Current server doesn't send a final confirmation after upload data phase.
#     else:
#         print("File upload failed during transfer.")
#         # Disconnect might have already happened in send_file_stream

#     return success

def do_upload_file(filepath):
    """Handles uploading a file."""
    if not logged_in_user or not current_connection:
        print("Please log in first.")
        return False
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        print(f"ERROR: File not found or is not a file: {filepath}")
        return False

    filename = os.path.basename(filepath)
    print(f"Preparing to upload '{filename}'...")

    # 1. Send upload request
    request = {"action": "upload_request", "username": logged_in_user, "filename": filename}
    if not send_request(current_connection, request): return False

    response = receive_response(current_connection)
    if not response or not response.get("success"):
        print(f"Server rejected upload: {response.get('message', 'Unknown error') if response else 'Connection error'}")
        return False

    print(f"Server ready. Encrypting and calculating encrypted size...")

    # 2. Pre-encrypt to calculate size (first pass)
    temp_encrypted_chunks = []
    chunk_size = BUFFER_SIZE - 64  # Leave room for crypto overhead
    total_encrypted_size = 0
    
    # First pass - encrypt all chunks to calculate total encrypted size
    file_reader = read_file_chunked(filepath, chunk_size)
    if file_reader is None:
        print("ERROR: Failed to read file.")
        disconnect_from_server()
        return False
        
    try:
        for plain_chunk in file_reader:
            if plain_chunk is None:
                print("ERROR: Encountered error while reading file.")
                disconnect_from_server()
                return False
                
            encrypted_chunk = encrypt_chunk(plain_chunk)
            if encrypted_chunk is None:
                print("ERROR: Encryption failed for chunk.")
                disconnect_from_server()
                return False
                
            temp_encrypted_chunks.append(encrypted_chunk)
            total_encrypted_size += len(encrypted_chunk)
            
        # 3. Send the correct encrypted file size
        print(f"Sending actual encrypted filesize: {total_encrypted_size}")
        try:
            current_connection.sendall(struct.pack('>Q', total_encrypted_size))
        except socket.error as e:
            print(f"ERROR sending filesize: {e}")
            disconnect_from_server()
            return False
            
        # 4. Send pre-encrypted chunks
        print(f"Uploading {len(temp_encrypted_chunks)} encrypted chunks...")
        total_bytes_sent = 0
        
        for chunk in temp_encrypted_chunks:
            try:
                current_connection.sendall(chunk)
                total_bytes_sent += len(chunk)
            except socket.error as e:
                print(f"ERROR sending chunk: {e}")
                disconnect_from_server()
                return False
                
        print(f"File stream sent ({total_bytes_sent} encrypted bytes). Waiting for server finalization (if any)...")
        return True
        
    except Exception as e:
        print(f"UNEXPECTED error during upload: {e}")
        traceback.print_exc()
        disconnect_from_server()
        return False


def do_download_file(file_uuid, save_dir="."):
    """Handles downloading a file."""
    if not logged_in_user or not current_connection:
        print("Please log in first.")
        return False
    if not file_uuid or not isinstance(file_uuid, str):
        print("Invalid File UUID specified.")
        return False

    print(f"Requesting download for UUID: {file_uuid}")

    # 1. Send download request
    request = {"action": "download_request", "username": logged_in_user, "file_uuid": file_uuid} # TODO: Send token
    if not send_request(current_connection, request): return False

    response = receive_response(current_connection)
    if not response or not response.get("success"):
        print(f"Server rejected download: {response.get('message', 'Unknown error') if response else 'Connection error'}")
        return False

    original_filename = response.get("filename", f"{file_uuid}_downloaded.enc") # Use provided name or default
    # Basic sanitization for save path
    safe_original_filename = "".join(c for c in original_filename if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()
    save_path = os.path.join(save_dir, safe_original_filename)
    print(f"Server ready. Receiving file to save as '{save_path}'...")

    # 2. Get encrypted stream receiver generator
    encrypted_stream_receiver = receive_file_stream(current_connection)

    # 3. Decrypt stream and write to file
    decrypted_stream_gen = decrypt_file_stream(encrypted_stream_receiver)
    success = write_file_chunked(save_path, decrypted_stream_gen)

    if success:
        print(f"File '{safe_original_filename}' downloaded and decrypted successfully.")
    else:
        print(f"File download or decryption failed for '{safe_original_filename}'.")
        # write_file_chunked should handle cleanup of partial file

    return success

def do_delete_file(file_uuid):
    """Handles deleting a file."""
    if not logged_in_user or not current_connection:
        print("Please log in first.")
        return False
    if not file_uuid or not isinstance(file_uuid, str):
        print("Invalid File UUID specified.")
        return False

    # Confirmation
    confirm = input(f"Are you sure you want to delete file with UUID {file_uuid}? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Deletion cancelled.")
        return False

    request = {"action": "delete", "username": logged_in_user, "file_uuid": file_uuid} # TODO: Send token
    success = False
    if send_request(current_connection, request):
        response = receive_response(current_connection)
        if response:
            print(f"Server: {response.get('message', 'No message.')}")
            success = response.get('success', False)
        # else: receive_response handles errors/disconnect
    return success

def do_share_file(file_uuid, share_with_user):
    """Handles sharing a file."""
    if not logged_in_user or not current_connection:
        print("Please log in first.")
        return False
    if not file_uuid or not isinstance(file_uuid, str) or \
       not share_with_user or not isinstance(share_with_user, str):
        print("Invalid File UUID or username to share with.")
        return False

    request = {
        "action": "share",
        "username": logged_in_user, # TODO: Send token
        "file_uuid": file_uuid,
        "share_with_username": share_with_user
    }
    success = False
    if send_request(current_connection, request):
        response = receive_response(current_connection)
        if response:
            print(f"Server: {response.get('message', 'No message.')}")
            success = response.get('success', False)
        # else: receive_response handles errors/disconnect
    return success

# ==================================================
# Section: Main Client UI Loop (原本在 main_client.py)
# ==================================================
def print_menu():
    """Prints the main menu based on login state."""
    print("\n--- Secure Storage Client ---")
    if logged_in_user:
        print(f"Logged in as: {logged_in_user}")
        print("  1. List Files")
        print("  2. Upload File")
        print("  3. Download File")
        print("  4. Delete File")
        print("  5. Share File")
        print("  9. Logout")
    else:
        print("  1. Register")
        print("  2. Login")
    print("  0. Exit")
    print("---------------------------")

def main_loop():
    """Main command-line interface loop."""
    while True:
        print_menu()
        choice = input("Enter choice: ").strip()

        if logged_in_user:
            if choice == '1':
                do_list_files()
            elif choice == '2':
                filepath = input("Enter full path of file to upload: ")
                if filepath:
                    do_upload_file(filepath)
                else:
                    print("Upload cancelled.")
            elif choice == '3':
                files = do_list_files() # List files first
                if files: # Only ask if there are files
                    uuid = input("Enter UUID of file to download: ")
                    savedir = input("Enter directory to save file (default: current): ") or "."
                    if uuid:
                        do_download_file(uuid, savedir)
                    else:
                        print("Download cancelled.")
            elif choice == '4':
                files = do_list_files() # List files first
                if files:
                     uuid = input("Enter UUID of file to delete: ")
                     if uuid:
                          do_delete_file(uuid)
                     else:
                          print("Deletion cancelled.")
            elif choice == '5':
                files = do_list_files() # List files first
                if files:
                     uuid = input("Enter UUID of file to share: ")
                     share_user = input("Enter username to share with: ")
                     if uuid and share_user:
                          do_share_file(uuid, share_user)
                     else:
                          print("Sharing cancelled.")
            elif choice == '9':
                disconnect_from_server() # Logout = disconnect
            elif choice == '0':
                disconnect_from_server()
                break
            else:
                print("Invalid choice.")
        else: # Not logged in
            if choice == '1':
                username = input("Enter username to register: ")
                password = getpass.getpass("Enter password: ")
                password2 = getpass.getpass("Confirm password: ")
                if password != password2:
                    print("Passwords do not match.")
                elif username and password:
                    do_register(username, password)
                else:
                    print("Username and password cannot be empty.")
            elif choice == '2':
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                if username and password:
                    do_login(username, password)
                else:
                     print("Username and password required.")
            elif choice == '0':
                break
            else:
                print("Invalid choice.")

    print("Exiting client.")

# ==================================================
# Section: Script Execution Start
# ==================================================
if __name__ == '__main__':
    if SECRET_KEY is None:
        print("FATAL: Client key initialization failed. Cannot continue.")
        sys.exit(1)
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nCtrl+C detected. Exiting.")
        disconnect_from_server()
    except Exception as e:
        print("\n!!! UNEXPECTED CLIENT ERROR !!!")
        traceback.print_exc()
        disconnect_from_server()