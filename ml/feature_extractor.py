"""
Feature Extractor for ML-based Encryption Selection

Extracts features from files for ML classification:
- File size (KB)
- File type/extension
- Shannon entropy (randomness measure)
- Sensitivity level (based on file type mapping)

Reference: Research paper on adaptive hybrid cryptography
"""

import os
import math
from pathlib import Path
from typing import Dict, Any, List, Optional
import struct


class FeatureExtractor:
    """
    Extracts features from files for ML-based encryption selection.
    """
    
    # File type sensitivity mappings
    # Higher values = more sensitive = needs stronger encryption
    SENSITIVITY_MAPPING = {
        # High sensitivity - financial/medical/personal
        'pdf': 0.8,
        'doc': 0.8,
        'docx': 0.8,
        'xls': 0.9,
        'xlsx': 0.9,
        'csv': 0.7,
        'txt': 0.5,
        
        # Medium sensitivity - archives/executables
        'zip': 0.6,
        'rar': 0.6,
        '7z': 0.6,
        'tar': 0.6,
        'gz': 0.6,
        'exe': 0.7,
        'dll': 0.7,
        
        # Lower sensitivity - media files
        'jpg': 0.3,
        'jpeg': 0.3,
        'png': 0.4,
        'gif': 0.3,
        'bmp': 0.3,
        'mp3': 0.2,
        'mp4': 0.3,
        'avi': 0.3,
        'mkv': 0.3,
        'wav': 0.2,
        
        # Code files - medium-high
        'py': 0.6,
        'js': 0.6,
        'java': 0.6,
        'c': 0.5,
        'cpp': 0.5,
        'h': 0.5,
        'cs': 0.6,
        
        # Config/data files
        'json': 0.5,
        'xml': 0.5,
        'yaml': 0.5,
        'yml': 0.5,
        'ini': 0.4,
        'cfg': 0.4,
        
        # Default for unknown types
        'default': 0.5
    }
    
    # File type category encoding for ML
    FILE_TYPE_CATEGORIES = {
        'document': ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'],
        'spreadsheet': ['xls', 'xlsx', 'csv', 'ods'],
        'archive': ['zip', 'rar', '7z', 'tar', 'gz'],
        'image': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp'],
        'video': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv'],
        'audio': ['mp3', 'wav', 'flac', 'aac', 'ogg'],
        'code': ['py', 'js', 'java', 'c', 'cpp', 'h', 'cs', 'php', 'rb'],
        'config': ['json', 'xml', 'yaml', 'yml', 'ini', 'cfg'],
        'executable': ['exe', 'dll', 'so', 'bin'],
        'other': []
    }
    
    def __init__(self):
        """Initialize feature extractor."""
        self._build_category_lookup()
    
    def _build_category_lookup(self):
        """Build reverse lookup for file extension to category."""
        self._ext_to_category = {}
        for category, extensions in self.FILE_TYPE_CATEGORIES.items():
            for ext in extensions:
                self._ext_to_category[ext.lower()] = category
    
    def calculate_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of a file.
        
        Entropy measures the randomness/unpredictability of data.
        - Low entropy (0-3): Highly structured/repetitive data
        - Medium entropy (3-6): Normal data files
        - High entropy (6-8): Random/encrypted/compressed data
        
        Args:
            file_path: Path to the file
            
        Returns:
            Shannon entropy value (0-8 bits per byte)
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            return round(entropy, 4)
            
        except Exception as e:
            print(f"Error calculating entropy: {e}")
            return 0.0
    
    def get_file_extension(self, file_path: str) -> str:
        """Get file extension without the dot, lowercase."""
        ext = os.path.splitext(file_path)[1].lower()
        return ext[1:] if ext.startswith('.') else ext
    
    def get_file_category(self, file_path: str) -> str:
        """Get file category based on extension."""
        ext = self.get_file_extension(file_path)
        return self._ext_to_category.get(ext, 'other')
    
    def get_sensitivity(self, file_path: str) -> float:
        """
        Get sensitivity score based on file type.
        
        Returns:
            Sensitivity score (0.0 - 1.0)
        """
        ext = self.get_file_extension(file_path)
        return self.SENSITIVITY_MAPPING.get(ext, self.SENSITIVITY_MAPPING['default'])
    
    def get_file_size_kb(self, file_path: str) -> float:
        """Get file size in kilobytes."""
        try:
            return os.path.getsize(file_path) / 1024
        except Exception:
            return 0.0
    
    def check_file_header(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze file header for additional insights.
        
        Returns dict with:
        - has_magic: Whether file has recognized magic bytes
        - is_compressed: Whether file appears compressed
        - is_encrypted: Whether file appears already encrypted
        """
        result = {
            'has_magic': False,
            'is_compressed': False,
            'is_encrypted': False
        }
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            if len(header) < 4:
                return result
            
            # Check for common magic bytes
            magic_signatures = {
                b'\x89PNG': ('png', False, False),
                b'\xFF\xD8\xFF': ('jpeg', False, False),
                b'GIF8': ('gif', False, False),
                b'%PDF': ('pdf', False, False),
                b'PK\x03\x04': ('zip', True, False),  # ZIP/DOCX/XLSX
                b'Rar!': ('rar', True, False),
                b'\x1f\x8b': ('gzip', True, False),
                b'7z\xBC\xAF': ('7z', True, False),
                b'\x00\x00\x00': ('possible_encrypted', False, True),
            }
            
            for magic, (ftype, compressed, encrypted) in magic_signatures.items():
                if header.startswith(magic):
                    result['has_magic'] = True
                    result['is_compressed'] = compressed
                    result['is_encrypted'] = encrypted
                    break
            
            return result
            
        except Exception:
            return result
    
    def extract_features(self, file_path: str) -> Dict[str, Any]:
        """
        Extract all features from a file for ML classification.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary containing:
            - size_kb: File size in kilobytes
            - extension: File extension
            - category: File category (document, image, etc.)
            - entropy: Shannon entropy (0-8)
            - sensitivity: Sensitivity score (0-1)
            - is_compressed: Whether file is compressed
            - normalized features for ML model
        """
        file_path = str(file_path)
        
        # Basic features
        size_kb = self.get_file_size_kb(file_path)
        extension = self.get_file_extension(file_path)
        category = self.get_file_category(file_path)
        entropy = self.calculate_entropy(file_path)
        sensitivity = self.get_sensitivity(file_path)
        
        # Header analysis
        header_info = self.check_file_header(file_path)
        
        # Normalized features for ML model
        # Size: log-scaled and normalized (assuming max ~100MB)
        size_normalized = min(1.0, math.log10(size_kb + 1) / 5) if size_kb > 0 else 0
        
        # Entropy normalized to 0-1 range (max entropy is 8)
        entropy_normalized = entropy / 8.0
        
        # Category encoded as numeric
        category_encoding = {
            'document': 0.9,
            'spreadsheet': 0.95,
            'code': 0.7,
            'config': 0.6,
            'archive': 0.5,
            'executable': 0.8,
            'image': 0.3,
            'video': 0.25,
            'audio': 0.2,
            'other': 0.5
        }
        category_score = category_encoding.get(category, 0.5)
        
        return {
            # Raw features
            'size_kb': round(size_kb, 2),
            'extension': extension,
            'category': category,
            'entropy': entropy,
            'sensitivity': sensitivity,
            'is_compressed': header_info['is_compressed'],
            'is_encrypted': header_info['is_encrypted'],
            
            # Normalized features for ML (these go into the model)
            'ml_features': {
                'size_normalized': round(size_normalized, 4),
                'entropy_normalized': round(entropy_normalized, 4),
                'category_score': category_score,
                'sensitivity': sensitivity
            },
            
            # Feature vector for direct ML input [size, entropy, category, sensitivity]
            'feature_vector': [
                size_normalized,
                entropy_normalized,
                category_score,
                sensitivity
            ]
        }
    
    def extract_features_batch(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Extract features from multiple files."""
        return [self.extract_features(fp) for fp in file_paths]


# Standalone functions for backward compatibility
def file_entropy(file_path: str) -> float:
    """Calculate file entropy (standalone function)."""
    extractor = FeatureExtractor()
    return extractor.calculate_entropy(file_path)


def extract_features(file_path: str) -> Dict[str, Any]:
    """Extract features from file (standalone function)."""
    extractor = FeatureExtractor()
    return extractor.extract_features(file_path)


if __name__ == '__main__':
    # Test the feature extractor
    import sys
    
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        extractor = FeatureExtractor()
        features = extractor.extract_features(test_file)
        
        print(f"\nFeature Analysis for: {test_file}")
        print("=" * 50)
        print(f"Size: {features['size_kb']:.2f} KB")
        print(f"Extension: {features['extension']}")
        print(f"Category: {features['category']}")
        print(f"Entropy: {features['entropy']:.4f} bits/byte")
        print(f"Sensitivity: {features['sensitivity']:.2f}")
        print(f"Compressed: {features['is_compressed']}")
        print(f"\nML Feature Vector: {features['feature_vector']}")
    else:
        print("Usage: python feature_extractor.py <file_path>")
