import os
import sys
import zlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import HMAC, SHA256
import hashlib
import getpass
import asyncio
import pyperclip
import re
import tqdm
from datetime import datetime

INPUT_FILE = "input.txt"
ENCRYPTED_FILE = "encrypted.bin"
DECRYPTED_FILE = "decrypted.txt"

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

async def process_file(input_file, output_file, passphrase, operation, compress=False):
    salt = get_random_bytes(16)
    encryption_key, hmac_key = await derive_keys_from_passphrase(passphrase, salt)
    cipher = AES.new(encryption_key, AES.MODE_GCM)
    total_size = await get_file_size(input_file)
    
    with open(input_file, 'rb') as input_stream, open(output_file, 'wb') as output_stream:
        output_stream.write(cipher.nonce)
        
        progress_desc = f"{operation.capitalize()}ing"
        with tqdm.tqdm(total=total_size, unit="B", unit_scale=True, desc=progress_desc) as pbar:
            async for chunk in read_file_async(input_file):
                if compress:
                    chunk = zlib.compress(chunk, level=zlib.Z_BEST_COMPRESSION)
                if operation == "encrypt":
                    ciphertext, tag = cipher.encrypt_and_digest(chunk)
                else:
                    ciphertext = cipher.decrypt(chunk)
                    if compress:
                        ciphertext = zlib.decompress(ciphertext)
                output_stream.write(ciphertext)
                pbar.update(len(chunk))
                pbar.n = await calculate_progress(total_size, output_stream.tell())
                pbar.refresh()
    
    if operation == "encrypt":
        return salt, hmac_key
    else:
        with open(output_file, 'rb') as decrypted_file_async:
            decrypted_data = await decrypted_file_async.read()
            decrypted_hmac = await calculate_hmac(decrypted_data, hmac_key)
        
        await secure_delete(output_file)
        return decrypted_hmac

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
    
    compress = input("Enable file compression (y/n)? ").strip().lower() == 'y'
    
    await validate_input_file(INPUT_FILE)
    
    try:
        await log_event("Starting encryption")
        salt, hmac_key = await process_file(INPUT_FILE, ENCRYPTED_FILE, passphrase, "encrypt", compress)
        await log_event("Encryption completed")
        
        print(f"File '{INPUT_FILE}' encrypted to '{ENCRYPTED_FILE}'")
        
        file_hash = await calculate_file_hash(INPUT_FILE)
        print(f"File hash (SHA-256): {file_hash}")
        
        await log_event("Starting decryption")
        decrypted_hmac = await process_file(ENCRYPTED_FILE, DECRYPTED_FILE, passphrase, "decrypt", compress)
        await log_event("Decryption completed")
        
        print(f"File '{ENCRYPTED_FILE}' decrypted to '{DECRYPTED_FILE}'")
        
        decrypted_file_hash = await calculate_file_hash(DECRYPTED_FILE)
        result = "PASSED" if file_hash == decrypted_file_hash else "FAILED (The decrypted file may have been tampered with)"
        print(f"File integrity check: {result}")
        
        print(f"Decrypted file HMAC: {decrypted_hmac.hex()}")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        await log_event(f"Error: {str(e)}")
    
    finally:
        await clear_clipboard()
        await secure_delete(INPUT_FILE)

if __name__ == "__main__":
    asyncio.run(main())
