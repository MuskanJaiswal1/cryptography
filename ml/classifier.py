"""
ML Classifier for Encryption Strategy Selection

Uses machine learning to predict the optimal encryption strategy
based on file features (size, entropy, type, sensitivity).

Model: Random Forest Classifier
Input: Feature vector [size_normalized, entropy_normalized, category_score, sensitivity]
Output: Security level (HIGH_SECURITY, MEDIUM_SECURITY, LOW_SECURITY)

Reference: Research paper on adaptive hybrid cryptography
"""

import os
import pickle
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import warnings

# Try to import sklearn, provide fallback if not available
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    warnings.warn("scikit-learn not installed. Using rule-based fallback classifier.")

from .feature_extractor import FeatureExtractor
from .strategies import (
    EncryptionStrategy, 
    SecurityLevel,
    get_strategy_from_prediction,
    get_strategy_config
)


class EncryptionClassifier:
    """
    ML-based classifier for selecting encryption strategies.
    
    Uses a Random Forest model trained on file features to predict
    the optimal security level, which maps to an encryption strategy.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the classifier.
        
        Args:
            model_path: Path to saved model file. If None, uses default path.
        """
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.scaler = None
        self.model_loaded = False
        
        # Default model path
        if model_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            self.model_path = base_dir / 'ml_models' / 'encryption_classifier.pkl'
        else:
            self.model_path = Path(model_path)
        
        # Try to load existing model
        self._load_model()
    
    def _load_model(self) -> bool:
        """Load saved model from disk."""
        if not self.model_path.exists():
            print(f"No saved model found at {self.model_path}")
            print("Using rule-based classification until model is trained.")
            return False
        
        try:
            with open(self.model_path, 'rb') as f:
                saved_data = pickle.load(f)
                self.model = saved_data.get('model')
                self.scaler = saved_data.get('scaler')
                self.model_loaded = True
                print(f"Model loaded from {self.model_path}")
                return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def _rule_based_classify(self, features: Dict[str, Any]) -> Tuple[str, float]:
        """
        Rule-based classification fallback when ML model is not available.
        
        Uses heuristics based on file features to determine security level.
        """
        ml_features = features.get('ml_features', {})
        
        size_norm = ml_features.get('size_normalized', 0.5)
        entropy_norm = ml_features.get('entropy_normalized', 0.5)
        category_score = ml_features.get('category_score', 0.5)
        sensitivity = ml_features.get('sensitivity', 0.5)
        
        # Calculate composite score
        # Weights: sensitivity is most important, then category, then entropy
        composite_score = (
            sensitivity * 0.35 +
            category_score * 0.30 +
            entropy_norm * 0.20 +
            (1 - size_norm) * 0.15  # Smaller files can afford stronger encryption
        )
        
        # Special rules
        # Already compressed/encrypted files don't need strongest encryption
        if features.get('is_compressed') or features.get('is_encrypted'):
            composite_score = min(composite_score, 0.6)
        
        # High entropy files (already random) don't benefit as much from multi-layer
        if entropy_norm > 0.85:
            composite_score = min(composite_score, 0.65)
        
        # Classify based on composite score
        if composite_score >= 0.65:
            return ('HIGH_SECURITY', composite_score)
        elif composite_score >= 0.40:
            return ('MEDIUM_SECURITY', composite_score)
        else:
            return ('LOW_SECURITY', composite_score)
    
    def classify(self, file_path: str) -> Dict[str, Any]:
        """
        Classify a file and return recommended encryption strategy.
        
        Args:
            file_path: Path to the file to classify
            
        Returns:
            Dictionary containing:
            - security_level: Predicted security level
            - strategy: Recommended EncryptionStrategy
            - confidence: Prediction confidence (0-1)
            - features: Extracted file features
            - strategy_config: Configuration for the strategy
        """
        # Extract features
        features = self.feature_extractor.extract_features(file_path)
        feature_vector = features['feature_vector']
        
        # Use ML model if available, otherwise fall back to rules
        if self.model_loaded and self.model is not None and SKLEARN_AVAILABLE:
            # Prepare features for ML model
            if self.scaler is not None:
                scaled_features = self.scaler.transform([feature_vector])
            else:
                scaled_features = [feature_vector]
            
            # Predict
            prediction = self.model.predict(scaled_features)[0]
            probabilities = self.model.predict_proba(scaled_features)[0]
            confidence = max(probabilities)
        else:
            # Rule-based fallback
            prediction, confidence = self._rule_based_classify(features)
        
        # Map to strategy
        strategy = get_strategy_from_prediction(prediction)
        strategy_config = get_strategy_config(strategy)
        
        return {
            'security_level': prediction,
            'strategy': strategy,
            'confidence': round(confidence, 4),
            'features': features,
            'strategy_config': strategy_config,
            'model_used': 'ml' if self.model_loaded else 'rule_based'
        }
    
    def classify_batch(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Classify multiple files."""
        return [self.classify(fp) for fp in file_paths]
    
    def train(self, training_data: List[Tuple[str, str]], save: bool = True) -> Dict[str, Any]:
        """
        Train the ML model on labeled data.
        
        Args:
            training_data: List of (file_path, security_level) tuples
            save: Whether to save the trained model
            
        Returns:
            Training metrics
        """
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn required for training. Install with: pip install scikit-learn")
        
        if len(training_data) < 10:
            raise ValueError("Need at least 10 training samples")
        
        # Extract features from training files
        X = []
        y = []
        
        for file_path, label in training_data:
            try:
                features = self.feature_extractor.extract_features(file_path)
                X.append(features['feature_vector'])
                y.append(label)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                continue
        
        if len(X) < 10:
            raise ValueError("Not enough valid training samples")
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            class_weight='balanced'  # Handle imbalanced classes
        )
        self.model.fit(X_scaled, y)
        self.model_loaded = True
        
        # Calculate training accuracy
        train_accuracy = self.model.score(X_scaled, y)
        
        # Get feature importances
        feature_names = ['size', 'entropy', 'category', 'sensitivity']
        importances = dict(zip(feature_names, self.model.feature_importances_))
        
        metrics = {
            'training_samples': len(X),
            'train_accuracy': round(train_accuracy, 4),
            'feature_importances': importances,
            'classes': list(self.model.classes_)
        }
        
        # Save model
        if save:
            self._save_model()
            metrics['model_saved'] = str(self.model_path)
        
        return metrics
    
    def _save_model(self):
        """Save model to disk."""
        # Ensure directory exists
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        save_data = {
            'model': self.model,
            'scaler': self.scaler
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(save_data, f)
        
        print(f"Model saved to {self.model_path}")


def predict_encryption_strategy(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to predict encryption strategy for a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Classification result with strategy recommendation
    """
    classifier = EncryptionClassifier()
    return classifier.classify(file_path)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        classifier = EncryptionClassifier()
        result = classifier.classify(test_file)
        
        print(f"\nEncryption Strategy Recommendation for: {test_file}")
        print("=" * 60)
        print(f"Security Level: {result['security_level']}")
        print(f"Strategy: {result['strategy'].value}")
        print(f"Confidence: {result['confidence']*100:.1f}%")
        print(f"Model Used: {result['model_used']}")
        print(f"\nFile Features:")
        print(f"  Size: {result['features']['size_kb']:.2f} KB")
        print(f"  Type: {result['features']['extension']} ({result['features']['category']})")
        print(f"  Entropy: {result['features']['entropy']:.4f} bits/byte")
        print(f"  Sensitivity: {result['features']['sensitivity']:.2f}")
        print(f"\nStrategy Details:")
        print(f"  {result['strategy_config']['name']}")
        print(f"  Algorithms: {', '.join(result['strategy_config']['algorithms'])}")
    else:
        print("Usage: python classifier.py <file_path>")
