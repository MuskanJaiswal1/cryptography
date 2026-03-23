"""
Training Script for Encryption Strategy ML Model

Generates synthetic training data and trains the Random Forest classifier.
The model learns to predict security levels based on file features.

Training data is generated based on realistic file characteristics:
- File size distribution
- Entropy patterns for different file types
- Category and sensitivity mappings

Run this script to train/retrain the model:
    python -m ml.train_model

Reference: Research paper on adaptive hybrid cryptography
"""

import os
import random
import pickle
from pathlib import Path
from typing import List, Tuple, Dict
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("ERROR: scikit-learn is required for training.")
    print("Install with: pip install scikit-learn")
    exit(1)


def generate_synthetic_training_data(n_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data based on realistic file characteristics.
    
    Features: [size_normalized, entropy_normalized, category_score, sensitivity]
    Labels: HIGH_SECURITY, MEDIUM_SECURITY, LOW_SECURITY
    
    The data is generated to reflect realistic patterns:
    - Documents (high sensitivity, medium entropy) → HIGH_SECURITY
    - Media files (low sensitivity, varied entropy) → LOW_SECURITY
    - Code/archives (medium sensitivity) → MEDIUM_SECURITY
    """
    X = []
    y = []
    
    # HIGH_SECURITY samples (documents, spreadsheets, sensitive data)
    for _ in range(n_samples // 3):
        size = random.uniform(0.1, 0.7)  # Typically smaller files
        entropy = random.uniform(0.4, 0.7)  # Text-like entropy
        category = random.uniform(0.8, 1.0)  # Document/spreadsheet
        sensitivity = random.uniform(0.7, 1.0)  # High sensitivity
        
        # Add some noise
        size += random.gauss(0, 0.05)
        entropy += random.gauss(0, 0.05)
        
        X.append([
            max(0, min(1, size)),
            max(0, min(1, entropy)),
            category,
            sensitivity
        ])
        y.append('HIGH_SECURITY')
    
    # MEDIUM_SECURITY samples (code, configs, archives)
    for _ in range(n_samples // 3):
        size = random.uniform(0.2, 0.8)  # Varied sizes
        entropy = random.uniform(0.5, 0.85)  # Medium-high entropy
        category = random.uniform(0.5, 0.8)  # Code/config/archive
        sensitivity = random.uniform(0.4, 0.7)  # Medium sensitivity
        
        # Add some noise
        size += random.gauss(0, 0.05)
        entropy += random.gauss(0, 0.05)
        
        X.append([
            max(0, min(1, size)),
            max(0, min(1, entropy)),
            category,
            sensitivity
        ])
        y.append('MEDIUM_SECURITY')
    
    # LOW_SECURITY samples (media files, large archives)
    for _ in range(n_samples - 2 * (n_samples // 3)):
        size = random.uniform(0.5, 1.0)  # Typically larger files
        entropy = random.uniform(0.7, 1.0)  # High entropy (compressed/media)
        category = random.uniform(0.1, 0.4)  # Media category
        sensitivity = random.uniform(0.1, 0.4)  # Low sensitivity
        
        # Add some noise
        size += random.gauss(0, 0.05)
        entropy += random.gauss(0, 0.05)
        
        X.append([
            max(0, min(1, size)),
            max(0, min(1, entropy)),
            category,
            sensitivity
        ])
        y.append('LOW_SECURITY')
    
    # Add edge cases
    edge_cases = [
        # Very small but sensitive document
        ([0.05, 0.45, 0.95, 0.95], 'HIGH_SECURITY'),
        # Large sensitive document
        ([0.9, 0.5, 0.9, 0.85], 'HIGH_SECURITY'),
        # Small media file
        ([0.1, 0.85, 0.25, 0.2], 'LOW_SECURITY'),
        # Encrypted archive (high entropy, medium sensitivity)
        ([0.7, 0.95, 0.5, 0.5], 'MEDIUM_SECURITY'),
        # Text config file
        ([0.05, 0.35, 0.6, 0.5], 'MEDIUM_SECURITY'),
    ]
    
    for features, label in edge_cases:
        X.append(features)
        y.append(label)
    
    return np.array(X), np.array(y)


def train_model(save_path: str = None) -> Dict:
    """
    Train the encryption strategy classifier.
    
    Args:
        save_path: Path to save the trained model
        
    Returns:
        Training metrics and model information
    """
    print("=" * 60)
    print("Training Encryption Strategy Classifier")
    print("=" * 60)
    
    # Generate synthetic training data
    print("\n[1/5] Generating synthetic training data...")
    X, y = generate_synthetic_training_data(n_samples=2000)
    print(f"Generated {len(X)} training samples")
    print(f"Class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
    
    # Split into train and test sets
    print("\n[2/5] Splitting into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Scale features
    print("\n[3/5] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest
    print("\n[4/5] Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1  # Use all CPU cores
    )
    model.fit(X_train_scaled, y_train)
    
    # Evaluate model
    print("\n[5/5] Evaluating model...")
    train_accuracy = model.score(X_train_scaled, y_train)
    test_accuracy = model.score(X_test_scaled, y_test)
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
    
    # Feature importances
    feature_names = ['size', 'entropy', 'category', 'sensitivity']
    importances = dict(zip(feature_names, model.feature_importances_))
    
    # Predictions for detailed metrics
    y_pred = model.predict(X_test_scaled)
    
    print("\n" + "=" * 60)
    print("TRAINING RESULTS")
    print("=" * 60)
    print(f"\nTrain Accuracy: {train_accuracy*100:.2f}%")
    print(f"Test Accuracy:  {test_accuracy*100:.2f}%")
    print(f"Cross-Val Mean: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*2*100:.2f}%)")
    
    print("\nFeature Importances:")
    for name, imp in sorted(importances.items(), key=lambda x: -x[1]):
        print(f"  {name}: {imp*100:.1f}%")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    classes = model.classes_
    print(f"{'':15} {'Predicted':^45}")
    print(f"{'':15} {' '.join(f'{c:15}' for c in classes)}")
    for i, row in enumerate(cm):
        print(f"{'Actual ' + classes[i]:15} {' '.join(f'{v:15}' for v in row)}")
    
    # Save model
    if save_path is None:
        base_dir = Path(__file__).resolve().parent.parent
        save_path = base_dir / 'ml_models' / 'encryption_classifier.pkl'
    else:
        save_path = Path(save_path)
    
    save_path.parent.mkdir(parents=True, exist_ok=True)
    
    save_data = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names,
        'classes': list(model.classes_),
        'metrics': {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std()
        }
    }
    
    with open(save_path, 'wb') as f:
        pickle.dump(save_data, f)
    
    print(f"\nModel saved to: {save_path}")
    
    return {
        'train_accuracy': train_accuracy,
        'test_accuracy': test_accuracy,
        'cv_scores': cv_scores.tolist(),
        'feature_importances': importances,
        'model_path': str(save_path)
    }


def retrain_with_real_data(labeled_files: List[Tuple[str, str]], 
                           existing_model_path: str = None) -> Dict:
    """
    Retrain/fine-tune the model with real labeled data.
    
    Args:
        labeled_files: List of (file_path, security_level) tuples
        existing_model_path: Path to existing model (for fine-tuning)
        
    Returns:
        Training metrics
    """
    from .feature_extractor import FeatureExtractor
    
    extractor = FeatureExtractor()
    
    print(f"Processing {len(labeled_files)} labeled files...")
    
    X = []
    y = []
    
    for file_path, label in labeled_files:
        try:
            features = extractor.extract_features(file_path)
            X.append(features['feature_vector'])
            y.append(label)
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    if len(X) < 10:
        raise ValueError("Need at least 10 valid samples for training")
    
    X = np.array(X)
    y = np.array(y)
    
    # Generate additional synthetic data to augment real data
    X_synthetic, y_synthetic = generate_synthetic_training_data(n_samples=500)
    
    # Combine real and synthetic data
    X_combined = np.vstack([X, X_synthetic])
    y_combined = np.concatenate([y, y_synthetic])
    
    # Train model
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_combined)
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_scaled, y_combined)
    
    # Save
    base_dir = Path(__file__).resolve().parent.parent
    save_path = base_dir / 'ml_models' / 'encryption_classifier.pkl'
    save_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(save_path, 'wb') as f:
        pickle.dump({'model': model, 'scaler': scaler}, f)
    
    print(f"Model retrained and saved to {save_path}")
    
    return {
        'real_samples': len(X),
        'total_samples': len(X_combined),
        'accuracy': model.score(X_scaled, y_combined)
    }


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print("Usage: python -m ml.train_model [save_path]")
        print("\nTrains the encryption strategy classifier using synthetic data.")
        print("The trained model will be saved to ml_models/encryption_classifier.pkl")
    else:
        save_path = sys.argv[1] if len(sys.argv) > 1 else None
        metrics = train_model(save_path)
        print("\n✓ Training complete!")
