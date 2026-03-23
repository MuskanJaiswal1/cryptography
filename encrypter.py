import os
import json
import base64
from datetime import datetime
from enum import Enum
from typing import Optional

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM, AESGCM, ChaCha20Poly1305)

import config
import tools


class EncryptionStrategy(Enum):
    """Encryption strategies for ML-driven selection."""
    STRONG = "STRONG"       # Multi-layer: rotate through all algorithms
    BALANCED = "BALANCED"   # AES-GCM only (authenticated encryption)
    FAST = "FAST"          # ChaCha20 only (speed optimized)


def readPlainText(filename) -> bytes:
    source_filename = config.TEMP_FILES_FOLDER / filename
    file = open(source_filename, 'rb')
    raw = b""
    for line in file:
        raw = raw + line
    file.close()
    return raw


def writeEncryptedText(filename, encryptedData: bytes):
    target_filename = config.ENCRYPTED_FOLDER / filename
    target_file = open(target_filename, 'wb')
    target_file.write(encryptedData)
    target_file.close()


def writeEncryptedKeys(encryptedKeys: bytes):
    target_file = open(str(config.RAW_DATA_FOLDER / "store_in_me.enc"), "wb")
    target_file.write(encryptedKeys)
    target_file.close()
    target_file.close()


def rsaKeyPairGeneration():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return {"private": private_key, "public": public_key}


def RSAAlgo(data: bytes, my_private_key, your_public_key):
    encryptedKeys = my_private_key.encrypt(data)
    encryptedKeys = your_public_key.encrypt(encryptedKeys)
    # All keys stored in store_in_me.enc encrypted with my_private_key as well as your_public_key
    writeEncryptedKeys(encryptedKeys)


# AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding.
def AESAlgo(data: bytes, key: bytes):
    f = Fernet(key)
    secret_data = f.encrypt(data)
    # All keys stored in store_in_me.enc encrypted with key_1
    writeEncryptedKeys(secret_data)


def AESAlgoRotated(filename, key1: bytes, key2: bytes):
    f = MultiFernet([Fernet(key1), Fernet(key2)])
    raw = readPlainText(filename)
    encryptedData = f.encrypt(raw)
    writeEncryptedText(filename, encryptedData)


def ChaChaAlgo(filename, key: bytes, nonce: bytes):
    aad = b"authenticated but unencrypted data"
    chacha = ChaCha20Poly1305(key)

    raw = readPlainText(filename)
    encryptedData = chacha.encrypt(nonce, raw, aad)
    writeEncryptedText(filename, encryptedData)


def AESGCMAlgo(filename, key: bytes, nonce: bytes):
    aad = b"authenticated but unencrypted data"
    aesgcm = AESGCM(key)
    raw = readPlainText(filename)
    encryptedData = aesgcm.encrypt(nonce, raw, aad)
    writeEncryptedText(filename, encryptedData)


def AESCCMAlgo(filename, key: bytes, nonce: bytes):
    aad = b"authenticated but unencrypted data"
    aesccm = AESCCM(key)

    raw = readPlainText(filename)
    encryptedData = aesccm.encrypt(nonce, raw, aad)
    writeEncryptedText(filename, encryptedData)


def encrypter(strategy: Optional[EncryptionStrategy] = None, strategy_source: str = 'ML Recommended'):
    """
    Encrypt files using the specified strategy.
    
    Args:
        strategy: Encryption strategy to use. If None, defaults to STRONG.
                 - STRONG: Rotate through AES-MultiFernet, ChaCha20, AES-GCM, AES-CCM
                 - BALANCED: Use AES-GCM for all chunks
                 - FAST: Use ChaCha20 for all chunks
    """
    # Default to STRONG if no strategy provided (backward compatible)
    if strategy is None:
        strategy = EncryptionStrategy.STRONG
    
    tools.empty_folder(str(config.KEY_FOLDER))
    tools.empty_folder(str(config.ENCRYPTED_FOLDER))
    
    # Generate all keys (some may not be used depending on strategy)
    key_1 = Fernet.generate_key()
    key_1_1 = Fernet.generate_key()
    key_1_2 = Fernet.generate_key()
    key_2 = ChaCha20Poly1305.generate_key()
    key_3 = AESGCM.generate_key(bit_length=128)
    key_4 = AESCCM.generate_key(bit_length=128)
    nonce13 = os.urandom(13)
    nonce12 = os.urandom(12)
    
    files = sorted(tools.list_dir(str(config.TEMP_FILES_FOLDER)))
    original_file_name = _read_original_filename()
    chunk_rows = []
    
    # Apply encryption based on strategy
    for index in range(0, len(files)):
        chunk_name = files[index]
        chunk_path = config.TEMP_FILES_FOLDER / chunk_name
        chunk_size_kb = round(os.path.getsize(chunk_path) / 1024, 2)

        if strategy == EncryptionStrategy.STRONG:
            # Rotate through all 4 algorithms (original behavior)
            if index % 4 == 0:
                AESAlgoRotated(chunk_name, key_1_1, key_1_2)
                chunk_rows.append(_chunk_row(
                    chunk_id=index,
                    chunk_name=chunk_name,
                    size_kb=chunk_size_kb,
                    algorithm='AES-MultiFernet',
                    key_type='Symmetric',
                    nonce_used='-'
                ))
            elif index % 4 == 1:
                ChaChaAlgo(chunk_name, key_2, nonce12)
                chunk_rows.append(_chunk_row(
                    chunk_id=index,
                    chunk_name=chunk_name,
                    size_kb=chunk_size_kb,
                    algorithm='ChaCha20',
                    key_type='AEAD',
                    nonce_used='nonce12'
                ))
            elif index % 4 == 2:
                AESGCMAlgo(chunk_name, key_3, nonce12)
                chunk_rows.append(_chunk_row(
                    chunk_id=index,
                    chunk_name=chunk_name,
                    size_kb=chunk_size_kb,
                    algorithm='AES-GCM',
                    key_type='AEAD',
                    nonce_used='nonce12'
                ))
            else:
                AESCCMAlgo(chunk_name, key_4, nonce13)
                chunk_rows.append(_chunk_row(
                    chunk_id=index,
                    chunk_name=chunk_name,
                    size_kb=chunk_size_kb,
                    algorithm='AES-CCM',
                    key_type='AEAD',
                    nonce_used='nonce13'
                ))
                
        elif strategy == EncryptionStrategy.BALANCED:
            # Use AES-GCM for all chunks (good security, good performance)
            AESGCMAlgo(chunk_name, key_3, nonce12)
            chunk_rows.append(_chunk_row(
                chunk_id=index,
                chunk_name=chunk_name,
                size_kb=chunk_size_kb,
                algorithm='AES-GCM',
                key_type='AEAD',
                nonce_used='nonce12'
            ))
            
        elif strategy == EncryptionStrategy.FAST:
            # Use ChaCha20 for all chunks (fastest)
            ChaChaAlgo(chunk_name, key_2, nonce12)
            chunk_rows.append(_chunk_row(
                chunk_id=index,
                chunk_name=chunk_name,
                size_kb=chunk_size_kb,
                algorithm='ChaCha20',
                key_type='AEAD',
                nonce_used='nonce12'
            ))
    
    # Store all keys (even unused ones) for consistency
    # Base64 encode binary keys to prevent separator collision
    secret_information = (key_1_1)+b":::::"+(key_1_2)+b":::::"+ \
        base64.b64encode(key_2)+b":::::"+ \
        base64.b64encode(key_3)+b":::::"+ \
        base64.b64encode(key_4)+b":::::"+ \
        base64.b64encode(nonce12)+b":::::"+ \
        base64.b64encode(nonce13)  # All the keys

    # Encrypting all the keys with algo1 using key_1
    AESAlgo(secret_information, key_1)
    
    # Store the strategy used in metadata for decryption
    _save_encryption_metadata(strategy, len(files))
    upload_id = _save_chunk_map(strategy, original_file_name, chunk_rows, strategy_source)
    
    public_key = open(str(config.KEY_FOLDER / "Main_Key.pem"), "wb")
    public_key.write(key_1)  # key_1 stored in Main_Key.pem
    public_key.close()
    tools.empty_folder(str(config.TEMP_FILES_FOLDER))

    return {
        'upload_id': upload_id,
        'file_name': original_file_name,
        'num_chunks': len(files)
    }


def _save_encryption_metadata(strategy: EncryptionStrategy, num_chunks: int):
    """
    Save encryption metadata for decryption.
    
    Args:
        strategy: The encryption strategy used
        num_chunks: Number of file chunks encrypted
    """
    metadata = {
        'strategy': strategy.value,
        'num_chunks': num_chunks,
        'version': '2.0'  # Version to indicate ML-enhanced encryption
    }
    
    metadata_path = config.RAW_DATA_FOLDER / 'encryption_metadata.json'
    with open(str(metadata_path), 'w') as f:
        json.dump(metadata, f)


def get_encryption_metadata():
    """
    Read encryption metadata.
    
    Returns:
        Dictionary with strategy and num_chunks, or None if not found
    """
    metadata_path = config.RAW_DATA_FOLDER / 'encryption_metadata.json'
    try:
        with open(str(metadata_path), 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Legacy encryption - no metadata, assume STRONG strategy
        return {'strategy': 'STRONG', 'num_chunks': 0, 'version': '1.0'}


def _read_original_filename() -> str:
    """Read original uploaded file name from metadata written by divider."""
    meta_path = config.RAW_DATA_FOLDER / 'meta_data.txt'
    if not meta_path.exists():
        return 'unknown'

    try:
        with open(str(meta_path), 'r', encoding='utf-8') as f:
            for row in f:
                if row.startswith('File_Name='):
                    return row.split('=', 1)[1].strip()
    except Exception:
        pass

    return 'unknown'


def _chunk_row(chunk_id: int, chunk_name: str, size_kb: float, algorithm: str,
               key_type: str, nonce_used: str) -> dict:
    return {
        'chunk_id': chunk_id,
        'chunk_name': chunk_name,
        'size_kb': size_kb,
        'algorithm': algorithm,
        'key_type': key_type,
        'nonce_used': nonce_used,
        'order': chunk_id + 1
    }


def _save_chunk_map(strategy: EncryptionStrategy, file_name: str, chunk_rows: list,
                    strategy_source: str = 'ML Recommended') -> str:
    """
    Save chunk-level encryption details into data/raw_data/chunk_map.json.
    Keeps both latest record and recent history for dashboard drill-down.
    """
    chunk_map_path = config.RAW_DATA_FOLDER / 'chunk_map.json'
    now = datetime.now().isoformat()
    upload_id = f"{int(datetime.now().timestamp() * 1000)}"

    record = {
        'upload_id': upload_id,
        'timestamp': now,
        'file_name': file_name,
        'strategy': strategy.value,
        'strategy_source': strategy_source,
        'total_chunks': len(chunk_rows),
        'chunks': chunk_rows
    }

    payload = {
        'latest_upload_id': upload_id,
        'latest': record,
        'history': [record]
    }

    if chunk_map_path.exists():
        try:
            with open(str(chunk_map_path), 'r', encoding='utf-8') as f:
                existing = json.load(f)
                history = existing.get('history', [])
                if isinstance(history, list):
                    history.append(record)
                    payload['history'] = history[-100:]
        except Exception:
            pass

    with open(str(chunk_map_path), 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)

    return upload_id
