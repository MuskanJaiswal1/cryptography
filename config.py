"""
Configuration management for Secure File Storage
Handles paths, encryption settings, and ML model configuration
"""
import os
from pathlib import Path

# Base directory - root of the project
BASE_DIR = Path(__file__).resolve().parent

# Data storage configuration
# You can override these with environment variables for production
DATA_DIR = os.getenv('DATA_DIR', BASE_DIR / 'data')

# Storage paths
UPLOAD_FOLDER = Path(os.getenv('UPLOAD_FOLDER', DATA_DIR / 'uploads'))
ENCRYPTED_FOLDER = Path(os.getenv('ENCRYPTED_FOLDER', DATA_DIR / 'encrypted'))
KEY_FOLDER = Path(os.getenv('KEY_FOLDER', DATA_DIR / 'keys'))
TEMP_FILES_FOLDER = Path(os.getenv('TEMP_FILES_FOLDER', DATA_DIR / 'temp_files'))
RAW_DATA_FOLDER = Path(os.getenv('RAW_DATA_FOLDER', DATA_DIR / 'raw_data'))
RESTORED_FILES_FOLDER = Path(os.getenv('RESTORED_FILES_FOLDER', DATA_DIR / 'restored'))

# File upload settings
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
                     'xls', 'xlsx', 'zip', 'rar', 'mp4', 'mp3', 'csv'}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
CHUNK_SIZE = 32 * 1024  # 32 KB for file division

# Encryption settings
ENCRYPTION_ALGORITHMS = ['AES_MULTIFERNET', 'CHACHA20', 'AES_GCM', 'AES_CCM']

# ML Model settings
ML_MODEL_DIR = Path(os.getenv('ML_MODEL_DIR', BASE_DIR / 'ml_models'))
ENABLE_ML_SELECTION = os.getenv('ENABLE_ML_SELECTION', 'True').lower() == 'true'

# Security settings
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Flask settings
DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', 8000))


def init_directories():
    """Create all required directories if they don't exist"""
    directories = [
        UPLOAD_FOLDER,
        ENCRYPTED_FOLDER,
        KEY_FOLDER,
        TEMP_FILES_FOLDER,
        RAW_DATA_FOLDER,
        RESTORED_FILES_FOLDER,
        ML_MODEL_DIR
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✓ Initialized: {directory}")


if __name__ == '__main__':
    print("Initializing storage directories...")
    init_directories()
    print("\nConfiguration Summary:")
    print(f"  Base Directory: {BASE_DIR}")
    print(f"  Data Directory: {DATA_DIR}")
    print(f"  Max File Size: {MAX_FILE_SIZE / (1024*1024)} MB")
    print(f"  Chunk Size: {CHUNK_SIZE / 1024} KB")
    print(f"  ML Selection: {'Enabled' if ENABLE_ML_SELECTION else 'Disabled'}")
