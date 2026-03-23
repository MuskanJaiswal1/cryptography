├── app.py                 # Main Flask application with ML integration
├── config.py              # Centralized configuration management
├── encrypter.py           # Encryption engine with strategy patterns
├── decrypter.py           # Metadata-driven decryption logic
├── divider.py             # File chunking (32KB default)
├── restore.py             # Chunk reassembly to original file
├── tools.py               # File system utilities
├── cleanup.py             # Storage maintenance
├── ml/                    # Machine Learning modules
│   ├── classifier.py      # RandomForest model for strategy selection
│   ├── feature_extractor.py # File analysis (entropy, size, type)
│   ├── security_scanner.py # Pre-upload malware detection
│   ├── anomaly_detector.py # Behavioral pattern analysis
│   ├── metrics.py         # Performance tracking and logging
│   └── strategies.py      # Encryption strategy definitions
├── templates/             # 8 HTML pages for the web interface
├── data/                  # All generated data (uploads, encrypted files, keys, metrics)
└── ml_models/             # Trained ML models (encryption_classifier.pkl)


Algorithms Used
Algorithm	Type	Usage
MultiFernet	Symmetric + authentication	STRONG strategy rotation
ChaCha20-Poly1305	AEAD	STRONG rotation + FAST strategy
AES-GCM	AEAD	STRONG rotation + BALANCED strategy
AES-CCM	AEAD	STRONG rotation only


Three Encryption Strategies
STRONG - Maximum security: Rotates through all 4 algorithms per chunk
BALANCED - AES-GCM only (good security + performance)
FAST - ChaCha20 only (speed-optimized)


# Initialize directories
python config.py

# Train/fine-tune ML model (if needed)
python ml/classifier.py

# Start the Flask app
python app.py

# Access at http://localhost:8000
