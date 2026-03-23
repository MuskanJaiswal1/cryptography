"""
Performance Evaluation & Metrics Module

Tracks and measures system performance metrics for evaluation:
- Encryption/decryption time
- Strategy distribution
- ML accuracy metrics
- Storage overhead
- Security metrics

Generates reports for viva and documentation.

Reference: Research paper on adaptive hybrid cryptography
"""

import os
import json
import time
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import defaultdict
import functools


class PerformanceTracker:
    """
    Tracks performance metrics for encryption/decryption operations.
    """
    
    def __init__(self, data_dir: str = None):
        """
        Initialize performance tracker.
        
        Args:
            data_dir: Directory for metrics data. Defaults to data/metrics/
        """
        if data_dir is None:
            base_dir = Path(__file__).resolve().parent.parent
            data_dir = base_dir / 'data' / 'metrics'
        
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.metrics_file = self.data_dir / 'performance_metrics.csv'
        self.summary_file = self.data_dir / 'summary_stats.json'
        
        # Initialize metrics file
        self._init_metrics_file()
        
        # In-memory cache for current session
        self._session_metrics = []
    
    def _init_metrics_file(self):
        """Initialize metrics CSV file with headers."""
        if not self.metrics_file.exists():
            with open(self.metrics_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'operation', 'file_name', 'file_type',
                    'file_size_kb', 'strategy', 'ml_confidence',
                    'security_risk', 'encryption_time_ms', 'decryption_time_ms',
                    'num_chunks', 'storage_overhead_percent', 'entropy_before',
                    'entropy_after', 'success'
                ])
    
    def record_encryption(self,
                         file_name: str,
                         file_type: str,
                         file_size_kb: float,
                         strategy: str,
                         ml_confidence: float,
                         security_risk: str,
                         encryption_time_ms: float,
                         num_chunks: int,
                         storage_overhead_percent: float,
                         entropy_before: float,
                         entropy_after: float = 0.0,
                         success: bool = True):
        """Record encryption operation metrics."""
        
        record = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'encryption',
            'file_name': file_name,
            'file_type': file_type,
            'file_size_kb': round(file_size_kb, 2),
            'strategy': strategy,
            'ml_confidence': round(ml_confidence, 4),
            'security_risk': security_risk,
            'encryption_time_ms': round(encryption_time_ms, 2),
            'decryption_time_ms': 0,
            'num_chunks': num_chunks,
            'storage_overhead_percent': round(storage_overhead_percent, 2),
            'entropy_before': round(entropy_before, 4),
            'entropy_after': round(entropy_after, 4),
            'success': success
        }
        
        self._write_record(record)
        self._session_metrics.append(record)
        
        return record
    
    def record_decryption(self,
                         file_name: str,
                         file_type: str,
                         file_size_kb: float,
                         strategy: str,
                         decryption_time_ms: float,
                         num_chunks: int,
                         success: bool = True):
        """Record decryption operation metrics."""
        
        record = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'decryption',
            'file_name': file_name,
            'file_type': file_type,
            'file_size_kb': round(file_size_kb, 2),
            'strategy': strategy,
            'ml_confidence': 0,
            'security_risk': '',
            'encryption_time_ms': 0,
            'decryption_time_ms': round(decryption_time_ms, 2),
            'num_chunks': num_chunks,
            'storage_overhead_percent': 0,
            'entropy_before': 0,
            'entropy_after': 0,
            'success': success
        }
        
        self._write_record(record)
        self._session_metrics.append(record)
        
        return record
    
    def _write_record(self, record: Dict[str, Any]):
        """Write a record to the metrics CSV file."""
        with open(self.metrics_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                record['timestamp'],
                record['operation'],
                record['file_name'],
                record['file_type'],
                record['file_size_kb'],
                record['strategy'],
                record['ml_confidence'],
                record['security_risk'],
                record['encryption_time_ms'],
                record['decryption_time_ms'],
                record['num_chunks'],
                record['storage_overhead_percent'],
                record['entropy_before'],
                record['entropy_after'],
                record['success']
            ])
    
    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """Get all recorded metrics."""
        metrics = []
        
        if not self.metrics_file.exists():
            return metrics
        
        with open(self.metrics_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert numeric fields
                row['file_size_kb'] = float(row['file_size_kb']) if row['file_size_kb'] else 0
                row['ml_confidence'] = float(row['ml_confidence']) if row['ml_confidence'] else 0
                row['encryption_time_ms'] = float(row['encryption_time_ms']) if row['encryption_time_ms'] else 0
                row['decryption_time_ms'] = float(row['decryption_time_ms']) if row['decryption_time_ms'] else 0
                row['num_chunks'] = int(row['num_chunks']) if row['num_chunks'] else 0
                row['storage_overhead_percent'] = float(row['storage_overhead_percent']) if row['storage_overhead_percent'] else 0
                row['success'] = row['success'] == 'True'
                metrics.append(row)
        
        return metrics
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Calculate summary statistics from all metrics.
        
        Returns comprehensive stats for evaluation/viva.
        """
        metrics = self.get_all_metrics()
        
        if not metrics:
            return {'total_operations': 0}
        
        # Separate by operation type
        encryptions = [m for m in metrics if m['operation'] == 'encryption']
        decryptions = [m for m in metrics if m['operation'] == 'decryption']
        
        # Strategy distribution
        strategy_dist = defaultdict(int)
        for m in encryptions:
            strategy_dist[m['strategy']] += 1
        
        # File type distribution
        file_type_dist = defaultdict(int)
        for m in encryptions:
            file_type_dist[m['file_type']] += 1
        
        # Risk level distribution
        risk_dist = defaultdict(int)
        for m in encryptions:
            if m['security_risk']:
                risk_dist[m['security_risk']] += 1
        
        # Performance stats
        enc_times = [m['encryption_time_ms'] for m in encryptions if m['encryption_time_ms'] > 0]
        dec_times = [m['decryption_time_ms'] for m in decryptions if m['decryption_time_ms'] > 0]
        
        # ML confidence stats
        confidences = [m['ml_confidence'] for m in encryptions if m['ml_confidence'] > 0]
        
        # Calculate averages
        avg_enc_time = sum(enc_times) / len(enc_times) if enc_times else 0
        avg_dec_time = sum(dec_times) / len(dec_times) if dec_times else 0
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        # Success rate
        total_ops = len(metrics)
        successful_ops = sum(1 for m in metrics if m['success'])
        success_rate = successful_ops / total_ops if total_ops > 0 else 0
        
        # Storage overhead
        overheads = [m['storage_overhead_percent'] for m in encryptions if m['storage_overhead_percent'] > 0]
        avg_overhead = sum(overheads) / len(overheads) if overheads else 0
        
        # Throughput by strategy
        throughput_by_strategy = {}
        for strategy in strategy_dist.keys():
            strat_metrics = [m for m in encryptions if m['strategy'] == strategy]
            if strat_metrics:
                total_size = sum(m['file_size_kb'] for m in strat_metrics)
                total_time = sum(m['encryption_time_ms'] for m in strat_metrics)
                if total_time > 0:
                    # KB per second
                    throughput_by_strategy[strategy] = round((total_size / total_time) * 1000, 2)
        
        summary = {
            'total_operations': total_ops,
            'total_encryptions': len(encryptions),
            'total_decryptions': len(decryptions),
            'success_rate': round(success_rate * 100, 2),
            
            'strategy_distribution': dict(strategy_dist),
            'file_type_distribution': dict(file_type_dist),
            'risk_level_distribution': dict(risk_dist),
            
            'performance': {
                'avg_encryption_time_ms': round(avg_enc_time, 2),
                'avg_decryption_time_ms': round(avg_dec_time, 2),
                'min_encryption_time_ms': round(min(enc_times), 2) if enc_times else 0,
                'max_encryption_time_ms': round(max(enc_times), 2) if enc_times else 0,
                'throughput_by_strategy_kbps': throughput_by_strategy
            },
            
            'ml_metrics': {
                'avg_confidence': round(avg_confidence * 100, 2),
                'min_confidence': round(min(confidences) * 100, 2) if confidences else 0,
                'max_confidence': round(max(confidences) * 100, 2) if confidences else 0
            },
            
            'storage': {
                'avg_overhead_percent': round(avg_overhead, 2),
                'total_data_processed_kb': round(sum(m['file_size_kb'] for m in metrics), 2)
            },
            
            'generated_at': datetime.now().isoformat()
        }
        
        # Save summary
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        return summary
    
    def generate_comparison_table(self) -> str:
        """
        Generate a comparison table for different strategies.
        
        Returns markdown-formatted table for documentation.
        """
        metrics = self.get_all_metrics()
        encryptions = [m for m in metrics if m['operation'] == 'encryption']
        
        if not encryptions:
            return "No encryption data available."
        
        # Group by strategy
        strategies = defaultdict(list)
        for m in encryptions:
            strategies[m['strategy']].append(m)
        
        # Build table
        lines = [
            "| Strategy | Files | Avg Size (KB) | Avg Time (ms) | Throughput (KB/s) | Avg Confidence |",
            "|----------|-------|---------------|---------------|-------------------|----------------|"
        ]
        
        for strategy, strat_metrics in sorted(strategies.items()):
            count = len(strat_metrics)
            avg_size = sum(m['file_size_kb'] for m in strat_metrics) / count
            avg_time = sum(m['encryption_time_ms'] for m in strat_metrics) / count
            throughput = (avg_size / avg_time * 1000) if avg_time > 0 else 0
            avg_conf = sum(m['ml_confidence'] for m in strat_metrics) / count
            
            lines.append(
                f"| {strategy} | {count} | {avg_size:.1f} | {avg_time:.1f} | "
                f"{throughput:.1f} | {avg_conf*100:.1f}% |"
            )
        
        return "\n".join(lines)
    
    def generate_file_type_table(self) -> str:
        """Generate a table showing ML decisions by file type."""
        metrics = self.get_all_metrics()
        encryptions = [m for m in metrics if m['operation'] == 'encryption']
        
        if not encryptions:
            return "No encryption data available."
        
        # Group by file type
        file_types = defaultdict(lambda: defaultdict(int))
        for m in encryptions:
            file_types[m['file_type']][m['strategy']] += 1
        
        # Build table
        lines = [
            "| File Type | STRONG | BALANCED | FAST | Total |",
            "|-----------|--------|----------|------|-------|"
        ]
        
        for ftype, strategies in sorted(file_types.items()):
            strong = strategies.get('STRONG', 0)
            balanced = strategies.get('BALANCED', 0)
            fast = strategies.get('FAST', 0)
            total = strong + balanced + fast
            
            lines.append(f"| {ftype} | {strong} | {balanced} | {fast} | {total} |")
        
        return "\n".join(lines)


class Timer:
    """Context manager for timing operations."""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.elapsed_ms = 0
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, *args):
        self.end_time = time.perf_counter()
        self.elapsed_ms = (self.end_time - self.start_time) * 1000


def timed_operation(func):
    """Decorator to time function execution."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        # Add timing to result if it's a dict
        if isinstance(result, dict):
            result['elapsed_ms'] = round(elapsed_ms, 2)
        
        return result
    return wrapper


# Global tracker instance
_tracker = None


def get_tracker() -> PerformanceTracker:
    """Get or create the global performance tracker instance."""
    global _tracker
    if _tracker is None:
        _tracker = PerformanceTracker()
    return _tracker


def record_encryption(**kwargs):
    """Convenience function to record encryption metrics."""
    tracker = get_tracker()
    return tracker.record_encryption(**kwargs)


def record_decryption(**kwargs):
    """Convenience function to record decryption metrics."""
    tracker = get_tracker()
    return tracker.record_decryption(**kwargs)


def get_summary():
    """Convenience function to get summary stats."""
    tracker = get_tracker()
    return tracker.get_summary_stats()


if __name__ == '__main__':
    # Test metrics tracking
    tracker = PerformanceTracker()
    
    # Record some test metrics
    tracker.record_encryption(
        file_name="test.pdf",
        file_type="document",
        file_size_kb=1024,
        strategy="STRONG",
        ml_confidence=0.95,
        security_risk="SAFE",
        encryption_time_ms=150.5,
        num_chunks=32,
        storage_overhead_percent=8.5,
        entropy_before=5.2,
        entropy_after=7.9
    )
    
    tracker.record_encryption(
        file_name="image.jpg",
        file_type="image",
        file_size_kb=2048,
        strategy="FAST",
        ml_confidence=0.88,
        security_risk="SAFE",
        encryption_time_ms=80.2,
        num_chunks=64,
        storage_overhead_percent=5.2,
        entropy_before=7.5,
        entropy_after=7.95
    )
    
    # Get summary
    summary = tracker.get_summary_stats()
    
    print("\n" + "=" * 60)
    print("PERFORMANCE METRICS SUMMARY")
    print("=" * 60)
    print(f"Total Operations: {summary['total_operations']}")
    print(f"Success Rate: {summary['success_rate']}%")
    print(f"\nStrategy Distribution: {summary['strategy_distribution']}")
    print(f"\nPerformance:")
    print(f"  Avg Encryption Time: {summary['performance']['avg_encryption_time_ms']} ms")
    print(f"\nML Metrics:")
    print(f"  Avg Confidence: {summary['ml_metrics']['avg_confidence']}%")
    
    print("\n" + tracker.generate_comparison_table())
