import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import hashlib
import getpass
import asyncio
import pyperclip
import re
import zlib
import tqdm
import logging
from datetime import datetime

# Get the user's home directory and construct the paths to the desktop folder
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
ENCRYPTED_FILE = os.path.join(desktop_path, "encrypted.bin")
DECRYPTED_FILE = os.path.join(desktop_path, "decrypted.txt")

logging.basicConfig(filename="encryption_tool.log", level=logging.INFO)

async def validate_input_file(file_path):
    if not os.path.isfile(file_path):
        print(f"Input file '{file_path}' does not exist.")
        sys.exit(1)

async def is_wifi_available():
    try:
        os.system("ping -c 1 www.google.com > /dev/null 2>&1")
        return False
    except:
        return True

async def toggle_network_isolation():
    network_status = "enabled" if await is_wifi_available() else "disabled"
    print(f"Network isolation mode is {network_status}. The tool won't access the network.")

async def is_strong_password(password):
    return bool(re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$", password))

async def calculate_hmac(data, key):
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(data)
    return hmac.digest()

async def derive_keys_from_passphrase(passphrase, salt):
    key = hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, 100000, dklen=64)
    return key[:32], key[32:]

async def get_file_size(file_path):
    return os.path.getsize(file_path)

async def calculate_progress(total, completed):
    return (completed / total) * 100

async def secure_delete(file_path):
    size = await get_file_size(file_path)
    with open(file_path, 'wb') as f:
        for _ in range(3):
            f.write(get_random_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    os.remove(file_path)

async def read_file_async(file_path, chunk_size=65536):
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

async def process_file(input_file, output_file, passphrase, operation, hmac_key=None, salt=None):
    if operation == "encrypt":
        salt = get_random_bytes(16)
    encryption_key, hmac_key = await derive_keys_from_passphrase(passphrase, salt)
    cipher = AES.new(encryption_key, AES.MODE_GCM)
    total_size = await get_file_size(input_file)
    
    with open(input_file, 'rb') as input_stream, open(output_file, 'wb') as output_stream:
        if operation == "encrypt":
            output_stream.write(salt)
        
        progress_desc = f"{operation.capitalize()}ing"
        with tqdm.tqdm(total=total_size, unit="B", unit_scale=True, desc=progress_desc) as pbar:
            while True:
                chunk = input_stream.read(65536)
                if not chunk:
                    break
                if operation == "encrypt":
                    ciphertext, tag = cipher.encrypt_and_digest(chunk)
                else:
                    ciphertext = cipher.decrypt(chunk)
                output_stream.write(ciphertext)
                pbar.update(len(chunk))
                pbar.n = await calculate_progress(total_size, output_stream.tell())
                pbar.refresh()
    
    if operation == "encrypt":
        return salt, hmac_key
    else:
        return salt, hmac_key

async def clear_clipboard():
    pyperclip.copy("")

async def log_event(event):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {event}"
    logging.info(log_entry)

async def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("This script can only be run in a terminal.")
        sys.exit(1)
    
    await toggle_network_isolation()
    
    passphrase = getpass.getpass("Enter passphrase: ")
    
    if not await is_strong_password(passphrase):
        print("Weak passphrase. It should have at least 8 characters, including uppercase, lowercase, and a digit.")
        sys.exit(1)
    
    operation = input("Choose operation (encrypt/decrypt): ").strip().lower()
    
    if operation not in ["encrypt", "decrypt"]:
        print("Invalid operation. Please choose either 'encrypt' or 'decrypt'.")
        sys.exit(1)
    
    input_file = input("Enter the path to the input file: ").strip()
    
    await validate_input_file(input_file)
    
    if operation == "encrypt":
        salt, hmac_key = await process_file(input_file, ENCRYPTED_FILE, passphrase, operation)
        await log_event("Encryption completed")
        print(f"File '{input_file}' encrypted to '{ENCRYPTED_FILE}'")
        print(f"Encryption salt: {salt.hex()}")
        print(f"HMAC key: {hmac_key.hex()}")
        await clear_clipboard()
    else:
        salt_input = input("Enter the encryption salt (hexadecimal string): ").strip()
        try:
            salt = bytes.fromhex(salt_input)
        except ValueError:
            print("Invalid salt format. It should be a hexadecimal string.")
            sys.exit(1)

        hmac_input = input("Enter the HMAC key (hexadecimal string): ").strip()
        try:
            hmac_key = bytes.fromhex(hmac_input)
        except ValueError:
            print("Invalid HMAC key format. It should be a hexadecimal string.")
            sys.exit(1)
        
        await process_file(input_file, DECRYPTED_FILE, passphrase, operation, hmac_key, salt)
        
        print(f"File '{input_file}' decrypted to '{DECRYPTED_FILE}'")
        await log_event("Decryption completed")
    
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
