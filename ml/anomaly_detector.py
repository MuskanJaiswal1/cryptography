"""
Anomaly Detection Module

Monitors file access patterns and detects suspicious behavior using
Isolation Forest algorithm.

Monitored Activities:
- File uploads/downloads
- Access times
- Access frequency
- IP addresses
- User patterns

Detection:
- Unusual access times (night access)
- High frequency access
- Multiple failed attempts
- Unusual file access patterns

Actions on Anomaly:
- Log alert
- Lock file
- Require re-authentication
- Force STRONG encryption

Reference: Research paper on adaptive hybrid cryptography with anomaly detection
"""

import os
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import pickle
import warnings

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    warnings.warn("scikit-learn not available. Using rule-based anomaly detection.")


class AccessLogger:
    """
    Logs file access events for anomaly detection.
    """
    
    def __init__(self, log_dir: str = None):
        """
        Initialize access logger.
        
        Args:
            log_dir: Directory for log files. Defaults to data/logs/
        """
        if log_dir is None:
            base_dir = Path(__file__).resolve().parent.parent
            log_dir = base_dir / 'data' / 'logs'
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.access_log_file = self.log_dir / 'access_logs.csv'
        self.alert_log_file = self.log_dir / 'anomaly_alerts.json'
        
        # Initialize log files if they don't exist
        self._init_logs()
    
    def _init_logs(self):
        """Initialize log files with headers."""
        if not self.access_log_file.exists():
            with open(self.access_log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'user_id', 'session_id', 'ip_address',
                    'operation', 'file_name', 'file_size', 'encryption_strategy',
                    'success', 'duration_ms'
                ])
        
        if not self.alert_log_file.exists():
            with open(self.alert_log_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
    
    def log_access(self, 
                   user_id: str = "anonymous",
                   session_id: str = None,
                   ip_address: str = "127.0.0.1",
                   operation: str = "upload",
                   file_name: str = "",
                   file_size: int = 0,
                   encryption_strategy: str = "",
                   success: bool = True,
                   duration_ms: int = 0):
        """
        Log a file access event.
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            ip_address: Client IP address
            operation: 'upload' or 'download'
            file_name: Name of the file
            file_size: Size in bytes
            encryption_strategy: Strategy used (STRONG, BALANCED, FAST)
            success: Whether operation succeeded
            duration_ms: Operation duration in milliseconds
        """
        timestamp = datetime.now().isoformat()
        
        with open(self.access_log_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, user_id, session_id or "", ip_address,
                operation, file_name, file_size, encryption_strategy,
                success, duration_ms
            ])
    
    def log_alert(self, alert_type: str, details: Dict[str, Any]):
        """Log an anomaly alert."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'details': details
        }
        
        # Read existing alerts
        alerts = []
        if self.alert_log_file.exists():
            with open(self.alert_log_file, 'r', encoding='utf-8') as f:
                try:
                    alerts = json.load(f)
                except json.JSONDecodeError:
                    alerts = []
        
        # Add new alert
        alerts.append(alert)
        
        # Keep only last 1000 alerts
        alerts = alerts[-1000:]
        
        # Write back
        with open(self.alert_log_file, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, indent=2)
        
        return alert
    
    def get_recent_logs(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get access logs from the last N hours."""
        logs = []
        cutoff = datetime.now() - timedelta(hours=hours)
        
        if not self.access_log_file.exists():
            return logs
        
        with open(self.access_log_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    timestamp = datetime.fromisoformat(row['timestamp'])
                    if timestamp >= cutoff:
                        logs.append(row)
                except (ValueError, KeyError):
                    continue
        
        return logs
    
    def get_user_stats(self, user_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get statistics for a specific user."""
        logs = self.get_recent_logs(hours)
        user_logs = [l for l in logs if l.get('user_id') == user_id]
        
        if not user_logs:
            return {'total_operations': 0}
        
        uploads = sum(1 for l in user_logs if l.get('operation') == 'upload')
        downloads = sum(1 for l in user_logs if l.get('operation') == 'download')
        failures = sum(1 for l in user_logs if l.get('success') == 'False')
        
        # Get access times
        hours_active = set()
        for log in user_logs:
            try:
                ts = datetime.fromisoformat(log['timestamp'])
                hours_active.add(ts.hour)
            except (ValueError, KeyError):
                pass
        
        return {
            'total_operations': len(user_logs),
            'uploads': uploads,
            'downloads': downloads,
            'failures': failures,
            'hours_active': list(hours_active),
            'failure_rate': failures / len(user_logs) if user_logs else 0
        }
    
    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent anomaly alerts."""
        if not self.alert_log_file.exists():
            return []
        
        with open(self.alert_log_file, 'r', encoding='utf-8') as f:
            try:
                alerts = json.load(f)
                return alerts[-limit:]
            except json.JSONDecodeError:
                return []


class AnomalyDetector:
    """
    Detects anomalous access patterns using Isolation Forest.
    """
    
    # Rule-based thresholds
    MAX_OPERATIONS_PER_HOUR = 50
    MAX_FAILURES_PER_HOUR = 10
    SUSPICIOUS_HOURS = {0, 1, 2, 3, 4, 5}  # 12 AM - 6 AM
    
    def __init__(self, model_path: str = None):
        """
        Initialize anomaly detector.
        
        Args:
            model_path: Path to saved model. Defaults to ml_models/anomaly_detector.pkl
        """
        if model_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            model_path = base_dir / 'ml_models' / 'anomaly_detector.pkl'
        
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.model_loaded = False
        
        self.logger = AccessLogger()
        
        # Try to load existing model
        self._load_model()
    
    def _load_model(self) -> bool:
        """Load saved model from disk."""
        if not self.model_path.exists() or not SKLEARN_AVAILABLE:
            return False
        
        try:
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.model_loaded = True
                return True
        except Exception as e:
            print(f"Error loading anomaly model: {e}")
            return False
    
    def _extract_features(self, logs: List[Dict[str, Any]], 
                          current_op: Dict[str, Any]) -> List[float]:
        """
        Extract features for anomaly detection.
        
        Features:
        - Hour of day (0-23)
        - Operations in last hour
        - Failures in last hour
        - Is weekend (0/1)
        - Unique IPs used
        - Time since last operation (minutes)
        """
        now = datetime.now()
        hour = now.hour
        is_weekend = 1 if now.weekday() >= 5 else 0
        
        # Count recent operations
        one_hour_ago = now - timedelta(hours=1)
        recent_logs = []
        for log in logs:
            try:
                ts = datetime.fromisoformat(log['timestamp'])
                if ts >= one_hour_ago:
                    recent_logs.append(log)
            except (ValueError, KeyError):
                pass
        
        ops_last_hour = len(recent_logs)
        failures_last_hour = sum(1 for l in recent_logs if l.get('success') == 'False')
        
        # Unique IPs
        unique_ips = len(set(l.get('ip_address', '') for l in recent_logs))
        
        # Time since last operation
        time_since_last = 60  # Default to 60 minutes
        if recent_logs:
            try:
                last_ts = datetime.fromisoformat(recent_logs[-1]['timestamp'])
                time_since_last = (now - last_ts).total_seconds() / 60
            except (ValueError, KeyError):
                pass
        
        return [
            hour,
            ops_last_hour,
            failures_last_hour,
            is_weekend,
            unique_ips,
            min(time_since_last, 1440)  # Cap at 24 hours
        ]
    
    def _rule_based_detect(self, features: List[float], 
                           user_stats: Dict[str, Any]) -> Tuple[bool, str, float]:
        """
        Rule-based anomaly detection fallback.
        
        Returns:
            Tuple of (is_anomaly, reason, confidence)
        """
        hour = features[0]
        ops_last_hour = features[1]
        failures_last_hour = features[2]
        
        # Check suspicious hours
        if hour in self.SUSPICIOUS_HOURS:
            return True, "Access during suspicious hours (late night)", 0.7
        
        # Check high operation count
        if ops_last_hour > self.MAX_OPERATIONS_PER_HOUR:
            return True, f"High operation frequency ({ops_last_hour} ops/hour)", 0.85
        
        # Check high failure rate
        if failures_last_hour > self.MAX_FAILURES_PER_HOUR:
            return True, f"High failure rate ({failures_last_hour} failures/hour)", 0.9
        
        # Check unusual failure rate for user
        failure_rate = user_stats.get('failure_rate', 0)
        if failure_rate > 0.3:
            return True, f"Unusual failure rate ({failure_rate*100:.1f}%)", 0.75
        
        return False, "Normal activity", 0.0
    
    def check_anomaly(self, 
                      user_id: str = "anonymous",
                      ip_address: str = "127.0.0.1",
                      operation: str = "upload",
                      file_name: str = "") -> Dict[str, Any]:
        """
        Check if current access pattern is anomalous.
        
        Args:
            user_id: User identifier
            ip_address: Client IP address
            operation: Type of operation
            file_name: Name of file being accessed
        
        Returns:
            Dictionary with:
            - is_anomaly: Whether pattern is anomalous
            - confidence: Confidence score (0-1)
            - reason: Explanation
            - action: Recommended action
        """
        # Get recent logs
        recent_logs = self.logger.get_recent_logs(hours=24)
        user_stats = self.logger.get_user_stats(user_id, hours=24)
        
        # Current operation info
        current_op = {
            'user_id': user_id,
            'ip_address': ip_address,
            'operation': operation,
            'file_name': file_name,
            'timestamp': datetime.now().isoformat()
        }
        
        # Extract features
        features = self._extract_features(recent_logs, current_op)
        
        # Detect anomaly
        if self.model_loaded and self.model is not None and SKLEARN_AVAILABLE:
            # Use ML model
            scaled_features = self.scaler.transform([features])
            prediction = self.model.predict(scaled_features)[0]
            score = self.model.score_samples(scaled_features)[0]
            
            # Isolation Forest: -1 = anomaly, 1 = normal
            is_anomaly = prediction == -1
            # Convert score to confidence (higher negative = more anomalous)
            confidence = max(0, min(1, -score))
            reason = "ML model detected unusual pattern" if is_anomaly else "Normal activity"
        else:
            # Use rule-based detection
            is_anomaly, reason, confidence = self._rule_based_detect(features, user_stats)
        
        # Determine action
        if is_anomaly:
            if confidence > 0.85:
                action = "BLOCK"
            elif confidence > 0.7:
                action = "FORCE_STRONG_ENCRYPTION"
            else:
                action = "LOG_ALERT"
        else:
            action = "ALLOW"
        
        result = {
            'is_anomaly': is_anomaly,
            'confidence': round(confidence, 4),
            'reason': reason,
            'action': action,
            'features': {
                'hour': features[0],
                'ops_last_hour': features[1],
                'failures_last_hour': features[2],
                'is_weekend': bool(features[3]),
                'unique_ips': features[4]
            },
            'user_stats': user_stats
        }
        
        # Log alert if anomaly detected
        if is_anomaly:
            self.logger.log_alert('anomaly_detected', {
                'user_id': user_id,
                'ip_address': ip_address,
                'operation': operation,
                'file_name': file_name,
                'confidence': confidence,
                'reason': reason,
                'action': action
            })
        
        return result
    
    def train_model(self, min_samples: int = 100) -> Dict[str, Any]:
        """
        Train the Isolation Forest model on historical data.
        
        Args:
            min_samples: Minimum samples required for training
            
        Returns:
            Training metrics
        """
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn required for training")
        
        # Get historical logs
        logs = self.logger.get_recent_logs(hours=24*30)  # Last 30 days
        
        if len(logs) < min_samples:
            # Generate synthetic normal data for initial training
            print(f"Insufficient logs ({len(logs)}). Generating synthetic data...")
            X = self._generate_synthetic_data(500)
        else:
            # Extract features from logs
            X = []
            for i in range(len(logs)):
                features = self._extract_features(logs[:i], logs[i])
                X.append(features)
            X = np.array(X)
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Expect 10% anomalies
            random_state=42
        )
        self.model.fit(X_scaled)
        self.model_loaded = True
        
        # Save model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler
            }, f)
        
        return {
            'samples_used': len(X),
            'model_path': str(self.model_path)
        }
    
    def _generate_synthetic_data(self, n_samples: int) -> np.ndarray:
        """Generate synthetic normal access patterns for initial training."""
        np.random.seed(42)
        
        # Normal working hours distribution (9 AM - 6 PM peak)
        hours = np.random.choice(
            range(24), 
            size=n_samples, 
            p=[0.01, 0.01, 0.01, 0.01, 0.01, 0.02, 0.03, 0.05, 
               0.08, 0.10, 0.10, 0.08, 0.08, 0.08, 0.08, 0.08,
               0.06, 0.04, 0.03, 0.02, 0.01, 0.01, 0.01, 0.01]
        )
        
        # Normal operation counts (1-20 per hour)
        ops = np.random.exponential(5, n_samples).clip(1, 30)
        
        # Low failure counts
        failures = np.random.poisson(0.5, n_samples).clip(0, 5)
        
        # Weekend distribution
        weekends = np.random.choice([0, 1], n_samples, p=[0.7, 0.3])
        
        # Unique IPs (usually 1-3)
        ips = np.random.poisson(1, n_samples).clip(1, 5)
        
        # Time since last op (minutes)
        time_gaps = np.random.exponential(10, n_samples).clip(0.5, 120)
        
        return np.column_stack([hours, ops, failures, weekends, ips, time_gaps])


# Global instances
_logger = None
_detector = None


def get_logger() -> AccessLogger:
    """Get or create the global access logger instance."""
    global _logger
    if _logger is None:
        _logger = AccessLogger()
    return _logger


def get_detector() -> AnomalyDetector:
    """Get or create the global anomaly detector instance."""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector


def log_access(**kwargs):
    """Convenience function to log an access event."""
    logger = get_logger()
    logger.log_access(**kwargs)


def check_anomaly(**kwargs) -> Dict[str, Any]:
    """Convenience function to check for anomalies."""
    detector = get_detector()
    return detector.check_anomaly(**kwargs)


if __name__ == '__main__':
    # Test anomaly detection
    detector = AnomalyDetector()
    
    # Train model with synthetic data
    print("Training anomaly detection model...")
    metrics = detector.train_model()
    print(f"Training complete: {metrics}")
    
    # Test detection
    print("\nTesting anomaly detection...")
    
    # Normal access
    result = detector.check_anomaly(
        user_id="user123",
        ip_address="192.168.1.1",
        operation="upload",
        file_name="document.pdf"
    )
    print(f"Normal access: {result['is_anomaly']} - {result['reason']}")
