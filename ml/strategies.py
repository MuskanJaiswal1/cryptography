"""
Encryption Strategies for ML-based Selection

Defines encryption strategies and their configurations based on security level.
Maps ML predictions to specific encryption algorithm combinations.

Security Levels:
- HIGH_SECURITY (STRONG): Multi-layer encryption, strongest algorithms
- MEDIUM_SECURITY (BALANCED): Good security with reasonable performance
- LOW_SECURITY (FAST): Speed-optimized, basic encryption

Reference: Research paper on adaptive hybrid cryptography
"""

from enum import Enum
from typing import Dict, List, Any


class SecurityLevel(Enum):
    """Security level classifications from ML model."""
    HIGH_SECURITY = "HIGH_SECURITY"
    MEDIUM_SECURITY = "MEDIUM_SECURITY"
    LOW_SECURITY = "LOW_SECURITY"


class EncryptionStrategy(Enum):
    """
    Encryption strategies mapped to security levels.
    
    STRONG: Maximum security - uses all encryption layers
    BALANCED: Good security with reasonable performance
    FAST: Speed optimized - single layer encryption
    """
    STRONG = "STRONG"       # Multi-layer: AES + MultiFernet + RSA-style protection
    BALANCED = "BALANCED"   # Moderate: AES-GCM (authenticated encryption)
    FAST = "FAST"          # Speed: ChaCha20 (fast stream cipher)


# Strategy configuration
STRATEGY_CONFIG = {
    EncryptionStrategy.STRONG: {
        'name': 'Strong Multi-Layer Encryption',
        'description': 'Maximum security using multiple encryption algorithms',
        'algorithms': ['AES_MULTIFERNET', 'AES_GCM', 'AES_CCM', 'CHACHA20'],
        'key_derivation': 'PBKDF2_HMAC',
        'chunk_encryption_pattern': 'rotating',  # Rotate through all algorithms
        'estimated_overhead': 1.15,  # 15% size overhead
        'performance_factor': 0.6,   # Slower
        'security_score': 1.0,
        'use_cases': [
            'Financial documents',
            'Medical records',
            'Personal identification',
            'Confidential business data',
            'Legal documents'
        ]
    },
    
    EncryptionStrategy.BALANCED: {
        'name': 'Balanced AES-GCM Encryption',
        'description': 'Authenticated encryption with good performance',
        'algorithms': ['AES_GCM'],
        'key_derivation': 'PBKDF2',
        'chunk_encryption_pattern': 'single',  # Same algorithm for all chunks
        'estimated_overhead': 1.08,  # 8% size overhead
        'performance_factor': 0.8,   # Moderate
        'security_score': 0.8,
        'use_cases': [
            'General documents',
            'Source code',
            'Configuration files',
            'Archives',
            'Regular business files'
        ]
    },
    
    EncryptionStrategy.FAST: {
        'name': 'Fast ChaCha20 Encryption',
        'description': 'Speed-optimized encryption for large files',
        'algorithms': ['CHACHA20'],
        'key_derivation': 'SHA256',
        'chunk_encryption_pattern': 'single',
        'estimated_overhead': 1.05,  # 5% size overhead
        'performance_factor': 1.0,   # Fastest
        'security_score': 0.7,
        'use_cases': [
            'Media files (images, videos, audio)',
            'Large archives',
            'Backup data',
            'Non-sensitive content'
        ]
    }
}


def get_strategy_config(strategy: EncryptionStrategy) -> Dict[str, Any]:
    """Get configuration for a specific encryption strategy."""
    return STRATEGY_CONFIG.get(strategy, STRATEGY_CONFIG[EncryptionStrategy.BALANCED])


def security_level_to_strategy(level: SecurityLevel) -> EncryptionStrategy:
    """Map security level to encryption strategy."""
    mapping = {
        SecurityLevel.HIGH_SECURITY: EncryptionStrategy.STRONG,
        SecurityLevel.MEDIUM_SECURITY: EncryptionStrategy.BALANCED,
        SecurityLevel.LOW_SECURITY: EncryptionStrategy.FAST
    }
    return mapping.get(level, EncryptionStrategy.BALANCED)


def get_strategy_from_prediction(prediction: str) -> EncryptionStrategy:
    """
    Convert ML prediction string to EncryptionStrategy.
    
    Args:
        prediction: One of 'HIGH_SECURITY', 'MEDIUM_SECURITY', 'LOW_SECURITY'
        
    Returns:
        Corresponding EncryptionStrategy
    """
    prediction = prediction.upper().strip()
    
    if prediction in ['HIGH_SECURITY', 'STRONG', 'HIGH']:
        return EncryptionStrategy.STRONG
    elif prediction in ['MEDIUM_SECURITY', 'BALANCED', 'MEDIUM']:
        return EncryptionStrategy.BALANCED
    elif prediction in ['LOW_SECURITY', 'FAST', 'LOW']:
        return EncryptionStrategy.FAST
    else:
        # Default to balanced for unknown predictions
        return EncryptionStrategy.BALANCED


def get_algorithm_sequence(strategy: EncryptionStrategy, num_chunks: int) -> List[str]:
    """
    Get the sequence of algorithms to use for each chunk.
    
    Args:
        strategy: The encryption strategy to use
        num_chunks: Number of file chunks
        
    Returns:
        List of algorithm names for each chunk
    """
    config = STRATEGY_CONFIG[strategy]
    algorithms = config['algorithms']
    pattern = config['chunk_encryption_pattern']
    
    if pattern == 'rotating':
        # Rotate through all algorithms
        return [algorithms[i % len(algorithms)] for i in range(num_chunks)]
    else:
        # Use same algorithm for all chunks
        return [algorithms[0]] * num_chunks


def estimate_encryption_time(file_size_kb: float, strategy: EncryptionStrategy) -> float:
    """
    Estimate encryption time in seconds.
    
    Args:
        file_size_kb: File size in kilobytes
        strategy: Encryption strategy
        
    Returns:
        Estimated time in seconds
    """
    config = STRATEGY_CONFIG[strategy]
    # Base rate: ~50MB/s for fast encryption
    base_rate_kbps = 50 * 1024  # KB per second
    adjusted_rate = base_rate_kbps * config['performance_factor']
    return file_size_kb / adjusted_rate


def get_strategy_summary(strategy: EncryptionStrategy) -> str:
    """Get a human-readable summary of the strategy."""
    config = STRATEGY_CONFIG[strategy]
    return f"{config['name']}: {config['description']} (Security: {config['security_score']*100:.0f}%)"


# Constants for easy access
STRONG = EncryptionStrategy.STRONG
BALANCED = EncryptionStrategy.BALANCED
FAST = EncryptionStrategy.FAST


if __name__ == '__main__':
    # Display strategy information
    print("=" * 60)
    print("Encryption Strategies Overview")
    print("=" * 60)
    
    for strategy in EncryptionStrategy:
        config = STRATEGY_CONFIG[strategy]
        print(f"\n{strategy.value}:")
        print(f"  Name: {config['name']}")
        print(f"  Algorithms: {', '.join(config['algorithms'])}")
        print(f"  Security Score: {config['security_score']*100:.0f}%")
        print(f"  Performance Factor: {config['performance_factor']}")
        print(f"  Use Cases: {', '.join(config['use_cases'][:3])}")
