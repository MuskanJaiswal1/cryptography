import json
import base64

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import (AESCCM, AESGCM,
                                                         ChaCha20Poly1305)

import config
import tools


def readEncryptedKeys():
    target_file = open(str(config.RAW_DATA_FOLDER / "store_in_me.enc"), "rb")
    encryptedKeys = b""
    for line in target_file:
        encryptedKeys = encryptedKeys + line
    target_file.close()
    return encryptedKeys


def readEncryptedText(filename):
    source_filename = config.ENCRYPTED_FOLDER / filename
    file = open(source_filename, 'rb')
    encryptedText = b""
    for line in file:
        encryptedText = encryptedText + line
    file.close()
    return encryptedText


def writePlainText(filename, plainText):
    target_filename = config.TEMP_FILES_FOLDER / filename
    target_file = open(target_filename, 'wb')
    target_file.write(plainText)
    target_file.close()


def AESAlgo(key):
    f = Fernet(key)
    encryptedKeys = readEncryptedKeys()
    secret_data = f.decrypt(encryptedKeys)
    return secret_data


def AESAlgoRotated(filename, key1, key2):
    f = MultiFernet([Fernet(key1), Fernet(key2)])
    encryptedText = readEncryptedText(filename)
    plainText = f.decrypt(encryptedText)
    writePlainText(filename, plainText)


def ChaChaAlgo(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    chacha = ChaCha20Poly1305(key)
    encryptedText = readEncryptedText(filename)
    plainText = chacha.decrypt(nonce, encryptedText, aad)
    writePlainText(filename, plainText)


def AESGCMAlgo(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    aesgcm = AESGCM(key)
    encryptedText = readEncryptedText(filename)
    plainText = aesgcm.decrypt(nonce, encryptedText, aad)
    writePlainText(filename, plainText)


def AESCCMAlgo(filename, key, nonce):
    aad = b"authenticated but unencrypted data"
    aesccm = AESCCM(key)
    encryptedText = readEncryptedText(filename)
    plainText = aesccm.decrypt(nonce, encryptedText, aad)
    writePlainText(filename, plainText)


def _get_encryption_metadata():
    """
    Read encryption metadata to determine decryption strategy.
    
    Returns:
        Dictionary with strategy info, or default for legacy files
    """
    metadata_path = config.RAW_DATA_FOLDER / 'encryption_metadata.json'
    try:
        with open(str(metadata_path), 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Legacy encryption - no metadata, assume STRONG strategy
        return {'strategy': 'STRONG', 'num_chunks': 0, 'version': '1.0'}


def decrypter():
    """
    Decrypt files using the strategy stored in metadata.
    
    Automatically detects the encryption strategy used and applies
    the correct decryption algorithm(s).
    """
    tools.empty_folder(str(config.TEMP_FILES_FOLDER))
    
    # Read encryption metadata to determine strategy
    metadata = _get_encryption_metadata()
    strategy = metadata.get('strategy', 'STRONG')
    version = metadata.get('version', '1.0')
    
    key_1 = b""
    list_directory = tools.list_dir(str(config.KEY_FOLDER))
    filename = config.KEY_FOLDER / list_directory[0]
    public_key = open(filename, "rb")
    for line in public_key:
        key_1 = key_1 + line
    public_key.close()
    secret_information = AESAlgo(key_1)
    list_information = secret_information.split(b':::::')
    key_1_1 = list_information[0]
    key_1_2 = list_information[1]
    
    # Handle both old (raw binary) and new (base64 encoded) key formats
    # New format (v2.0+) uses base64 to prevent separator collision
    try:
        if version >= '2.0':
            # New format: base64 encoded
            key_2 = base64.b64decode(list_information[2])
            key_3 = base64.b64decode(list_information[3])
            key_4 = base64.b64decode(list_information[4])
            nonce12 = base64.b64decode(list_information[5])
            nonce13 = base64.b64decode(list_information[6])
        else:
            # Old format: raw binary (for backward compatibility)
            key_2 = list_information[2]
            key_3 = list_information[3]
            key_4 = list_information[4]
            nonce12 = list_information[5]
            nonce13 = list_information[6]
        
        # Validate key sizes
        if len(key_3) not in [16, 24, 32]:
            raise ValueError(f"Invalid AESGCM key size: {len(key_3)} bytes")
            
    except Exception as e:
        print(f"Key parsing error: {e}, trying fallback...")
        # Fallback: try raw binary if base64 fails
        key_2 = list_information[2]
        key_3 = list_information[3]
        key_4 = list_information[4]
        nonce12 = list_information[5]
        nonce13 = list_information[6]
    
    files = sorted(tools.list_dir(str(config.ENCRYPTED_FOLDER)))
    
    # Decrypt based on strategy
    for index in range(0, len(files)):
        if strategy == 'STRONG':
            # Rotate through all 4 algorithms (original behavior)
            if index % 4 == 0:
                AESAlgoRotated(files[index], key_1_1, key_1_2)
            elif index % 4 == 1:
                ChaChaAlgo(files[index], key_2, nonce12)
            elif index % 4 == 2:
                AESGCMAlgo(files[index], key_3, nonce12)
            else:
                AESCCMAlgo(files[index], key_4, nonce13)
                
        elif strategy == 'BALANCED':
            # All chunks were encrypted with AES-GCM
            AESGCMAlgo(files[index], key_3, nonce12)
            
        elif strategy == 'FAST':
            # All chunks were encrypted with ChaCha20
            ChaChaAlgo(files[index], key_2, nonce12)
