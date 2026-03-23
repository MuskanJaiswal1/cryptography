"""
ML Module for Adaptive Encryption Selection

This module implements machine learning-based encryption strategy selection
based on file characteristics as described in the research paper.

Components:
- feature_extractor: Extracts file features (size, type, entropy, sensitivity)
- classifier: ML model for predicting optimal encryption strategy
- strategies: Encryption strategy definitions and mappings
- security_scanner: Pre-upload malware detection
- anomaly_detector: Access pattern anomaly detection
- metrics: Performance tracking and evaluation
"""

from .feature_extractor import FeatureExtractor
from .classifier import EncryptionClassifier
from .strategies import EncryptionStrategy, get_strategy_config
from .security_scanner import SecurityScanner, scan_file, RiskLevel
from .anomaly_detector import AnomalyDetector, AccessLogger, check_anomaly, log_access
from .metrics import PerformanceTracker, Timer, get_summary, record_encryption, record_decryption

__all__ = [
    'FeatureExtractor', 
    'EncryptionClassifier', 
    'EncryptionStrategy', 
    'get_strategy_config',
    'SecurityScanner',
    'scan_file',
    'RiskLevel',
    'AnomalyDetector',
    'AccessLogger',
    'check_anomaly',
    'log_access',
    'PerformanceTracker',
    'Timer',
    'get_summary',
    'record_encryption',
    'record_decryption'
]
