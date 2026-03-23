"""
Test script for ML-based encryption strategy selection.

This script demonstrates the ML pipeline by:
1. Classifying various file types
2. Showing the predicted encryption strategy
3. Displaying file features used for classification

Run with: python test_ml.py [file_path]
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.classifier import EncryptionClassifier
from ml.feature_extractor import FeatureExtractor
from ml.strategies import EncryptionStrategy, get_strategy_config


def test_classifier(file_path: str):
    """Test the ML classifier on a single file."""
    print("=" * 60)
    print("ML-Based Encryption Strategy Prediction")
    print("=" * 60)
    
    classifier = EncryptionClassifier()
    result = classifier.classify(file_path)
    
    print(f"\nFile: {file_path}")
    print(f"Security Level: {result['security_level']}")
    print(f"Strategy: {result['strategy'].value}")
    print(f"Confidence: {result['confidence']*100:.1f}%")
    print(f"Model Used: {result['model_used']}")
    
    print("\nFile Features:")
    features = result['features']
    print(f"  Size: {features['size_kb']:.2f} KB")
    print(f"  Extension: {features['extension']}")
    print(f"  Category: {features['category']}")
    print(f"  Entropy: {features['entropy']:.4f} bits/byte")
    print(f"  Sensitivity: {features['sensitivity']:.2f}")
    print(f"  Compressed: {features['is_compressed']}")
    
    print("\nStrategy Configuration:")
    config = result['strategy_config']
    print(f"  Name: {config['name']}")
    print(f"  Algorithms: {', '.join(config['algorithms'])}")
    print(f"  Security Score: {config['security_score']*100:.0f}%")
    print(f"  Performance Factor: {config['performance_factor']}")
    
    return result


def test_multiple_files():
    """Test the classifier on multiple file types."""
    print("Testing ML Classifier on Various Files")
    print("=" * 60)
    
    # Find some test files in the project
    test_files = []
    
    # Python files
    if os.path.exists('app.py'):
        test_files.append('app.py')
    if os.path.exists('encrypter.py'):
        test_files.append('encrypter.py')
    
    # Text files
    if os.path.exists('README.md'):
        test_files.append('README.md')
    if os.path.exists('requirements.txt'):
        test_files.append('requirements.txt')
    
    # HTML files
    if os.path.exists('templates/index.html'):
        test_files.append('templates/index.html')
    
    classifier = EncryptionClassifier()
    
    print(f"\n{'File':<30} {'Security Level':<18} {'Strategy':<12} {'Confidence':<12}")
    print("-" * 72)
    
    for file_path in test_files:
        try:
            result = classifier.classify(file_path)
            print(f"{file_path:<30} {result['security_level']:<18} "
                  f"{result['strategy'].value:<12} {result['confidence']*100:.1f}%")
        except Exception as e:
            print(f"{file_path:<30} Error: {e}")
    
    print("\n" + "=" * 60)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Test specific file
        test_classifier(sys.argv[1])
    else:
        # Test multiple files
        test_multiple_files()
        
        print("\nTo test a specific file, run:")
        print("  python test_ml.py <file_path>")
