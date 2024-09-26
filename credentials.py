import os, json
import psycopg2
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Global variable to cache the credentials
_cached_credentials = None

def load_credentials(file_path: str) -> dict:
    global _cached_credentials

    # Check if credentials are already cached
    if _cached_credentials is not None:
        return _cached_credentials

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Credentials file not found: {file_path}")

    with open(file_path, 'r') as file:
        _cached_credentials = json.load(file)

    return _cached_credentials

# Key derivation function for generating a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1
    )
    return kdf.derive(password.encode())


# Encrypt the credentials using AES-GCM for authenticated encryption
def encrypt_credentials(password: str, credentials: str) -> (bytes, bytes, bytes):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Generate a random nonce for AES-GCM
    encrypted_credentials = aesgcm.encrypt(nonce, credentials.encode(), None)
    return salt, nonce, encrypted_credentials


# Decrypt the credentials
def decrypt_credentials(password: str, salt: bytes, nonce: bytes, encrypted_credentials: bytes) -> str:
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_credentials, None).decode()


# Store the credentials securely in PostgreSQL
def store_credentials(imap_server: str, email: str, password: str, encryption_key: str):
    salt, nonce, encrypted_password = encrypt_credentials(encryption_key, password)

    # Load credentials
    credentials = load_credentials("credentials.json")

    conn = psycopg2.connect(
        dbname=credentials.get('dbname'),
        user=credentials.get('user'),
        password=credentials.get('password'),
        host=credentials.get('host'),
        port=credentials.get('port')
    )
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        user_id BIGSERIAL PRIMARY KEY,
        imap_server TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        salt BYTEA NOT NULL,
        nonce BYTEA NOT NULL,
        encrypted_password BYTEA NOT NULL
    )
    """)

    # Insert the encrypted credentials
    cursor.execute("""
    INSERT INTO credentials (imap_server, email, salt, nonce, encrypted_password)
    VALUES (%s, %s, %s, %s, %s)
    ON CONFLICT (email) DO UPDATE 
    SET imap_server = EXCLUDED.imap_server, 
        email = EXCLUDED.email,
        salt = EXCLUDED.salt,
        nonce = EXCLUDED.nonce,
        encrypted_password = EXCLUDED.encrypted_password
    """, (imap_server, email, psycopg2.Binary(salt), psycopg2.Binary(nonce), psycopg2.Binary(encrypted_password)))

    conn.commit()
    cursor.close()
    conn.close()

# Retrieve and decrypt the credentials from PostgreSQL
def retrieve_credentials(email: str, encryption_key: str):
    # Load credentials
    credentials = load_credentials("credentials.json")

    conn = psycopg2.connect(
        dbname=credentials.get('dbname'),
        user=credentials.get('user'),
        password=credentials.get('password'),
        host=credentials.get('host'),
        port=credentials.get('port')
    )
    cursor = conn.cursor()

    # Fetch the encrypted credentials
    cursor.execute("""
    SELECT imap_server, email, salt, nonce, encrypted_password
    FROM credentials
    WHERE email = %s
    """, (email,))

    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        imap_server, email, salt, nonce, encrypted_password = result
        decrypted_password = decrypt_credentials(encryption_key, bytes(salt), bytes(nonce), bytes(encrypted_password))
        return imap_server, email, decrypted_password
    else:
        raise ValueError("No credentials found with email " + email)