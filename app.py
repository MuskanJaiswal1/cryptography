import os
import time
import json
import math
import csv
import io
from datetime import datetime

from flask import Flask, flash, redirect, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename

import config
import decrypter as dec
import divider as dv
import encrypter as enc
import restore as rst
import tools

# ML-based encryption selection
try:
    from ml.classifier import EncryptionClassifier
    from ml.strategies import EncryptionStrategy
    from ml.security_scanner import SecurityScanner, RiskLevel
    from ml.anomaly_detector import AnomalyDetector, AccessLogger
    from ml.metrics import PerformanceTracker, Timer
    ML_AVAILABLE = True
    # Initialize components once
    ml_classifier = EncryptionClassifier()
    security_scanner = SecurityScanner()
    anomaly_detector = AnomalyDetector()
    access_logger = AccessLogger()
    performance_tracker = PerformanceTracker()
except ImportError as e:
    print(f"Warning: ML module not available ({e}). Using default encryption.")
    ML_AVAILABLE = False
    ml_classifier = None
    security_scanner = None
    anomaly_detector = None
    access_logger = None
    performance_tracker = None

# Initialize storage directories
config.init_directories()

ALLOWED_KEY_EXTENSIONS = set(['pem'])

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE

#port = int(os.getenv('PORT', 8000))


def allowed_key_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_KEY_EXTENSIONS


def _load_chunk_map_data():
    """Load chunk map metadata from data/raw_data/chunk_map.json."""
    chunk_map_path = config.RAW_DATA_FOLDER / 'chunk_map.json'
    if not chunk_map_path.exists():
        return {'latest_upload_id': None, 'latest': None, 'history': []}

    try:
        with open(str(chunk_map_path), 'r', encoding='utf-8') as f:
            payload = json.load(f)
            payload.setdefault('latest_upload_id', None)
            payload.setdefault('latest', None)
            payload.setdefault('history', [])
            return payload
    except Exception:
        return {'latest_upload_id': None, 'latest': None, 'history': []}


def _find_chunk_record(history, upload_id):
    """Find chunk-map record by upload_id from history."""
    if not upload_id:
        return None

    for item in reversed(history):
        if item.get('upload_id') == upload_id:
            return item

    return None


def _normalize_filename(filename):
    """Normalize file names for cross-source matching."""
    return secure_filename((filename or '').strip()).lower()


def _match_upload_id_for_metric(row, history):
    """
    Match dashboard metric row to chunk-map history.
    Uses file name + strategy + nearest timestamp.
    """
    file_name = row.get('file_name', '')
    strategy = row.get('strategy', '')
    ts_text = row.get('timestamp', '')
    normalized_metric_file = _normalize_filename(file_name)

    try:
        metric_ts = datetime.fromisoformat(ts_text)
    except Exception:
        metric_ts = None

    candidates = []
    for item in history:
        normalized_history_file = _normalize_filename(item.get('file_name', ''))
        if normalized_history_file != normalized_metric_file:
            continue
        if strategy and item.get('strategy') != strategy:
            continue

        if metric_ts:
            try:
                rec_ts = datetime.fromisoformat(item.get('timestamp', ''))
                delta = abs((metric_ts - rec_ts).total_seconds())
            except Exception:
                delta = 10**9
        else:
            delta = 10**9

        candidates.append((delta, item))

    # Fallback: match by normalized file name and nearest timestamp,
    # even if strategy differs.
    if not candidates:
        for item in history:
            normalized_history_file = _normalize_filename(item.get('file_name', ''))
            if normalized_history_file != normalized_metric_file:
                continue

            if metric_ts:
                try:
                    rec_ts = datetime.fromisoformat(item.get('timestamp', ''))
                    delta = abs((metric_ts - rec_ts).total_seconds())
                except Exception:
                    delta = 10**9
            else:
                delta = 10**9

            candidates.append((delta, item))

    if not candidates:
        return None

    candidates.sort(key=lambda c: c[0])
    best = candidates[0][1]
    return best.get('upload_id')


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_iso_datetime(value):
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return datetime.min


def _read_encryption_metrics_rows():
    """Read and normalize encryption rows from metrics CSV."""
    metrics_file = config.DATA_DIR / 'metrics' / 'performance_metrics.csv'
    if not metrics_file.exists():
        return []

    rows = []
    with open(metrics_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for raw in reader:
            if raw.get('operation', 'encryption') != 'encryption':
                continue

            timestamp_raw = raw.get('timestamp', '')
            row = {
                'timestamp_raw': timestamp_raw,
                'timestamp': timestamp_raw[:16] if timestamp_raw else 'N/A',
                'timestamp_dt': _parse_iso_datetime(timestamp_raw),
                'file_name': raw.get('file_name', 'Unknown'),
                'file_type': raw.get('file_type', 'Unknown'),
                'strategy': raw.get('strategy', 'N/A'),
                'security_risk': raw.get('security_risk', 'N/A'),
                'encryption_time_ms': _safe_float(raw.get('encryption_time_ms', 0)),
                'file_size_kb': _safe_float(raw.get('file_size_kb', 0)),
                'num_chunks': _safe_int(raw.get('num_chunks', 0)),
                'storage_overhead_percent': _safe_float(raw.get('storage_overhead_percent', 0)),
                'entropy_before': _safe_float(raw.get('entropy_before', 0)),
                'entropy_after': _safe_float(raw.get('entropy_after', 0)),
                'ml_confidence': _safe_float(raw.get('ml_confidence', 0)),
                'success': str(raw.get('success', 'True')).lower() == 'true'
            }
            rows.append(row)

    return rows


def _calculate_trend(all_rows, key, lower_is_better=False):
    """Return trend metadata comparing recent 10 rows vs previous 10 rows."""
    ordered = sorted(all_rows, key=lambda r: r['timestamp_dt'])
    if len(ordered) < 2:
        return {'arrow': '-', 'percent': 0.0, 'direction_class': 'text-gray-400'}

    recent = ordered[-10:]
    previous = ordered[-20:-10] if len(ordered) > 10 else ordered[:-10]
    if not previous:
        return {'arrow': '-', 'percent': 0.0, 'direction_class': 'text-gray-400'}

    recent_avg = sum(_safe_float(r.get(key, 0)) for r in recent) / len(recent)
    previous_avg = sum(_safe_float(r.get(key, 0)) for r in previous) / len(previous)

    if previous_avg == 0:
        return {'arrow': '-', 'percent': 0.0, 'direction_class': 'text-gray-400'}

    delta_percent = ((recent_avg - previous_avg) / previous_avg) * 100
    if lower_is_better:
        improved = delta_percent < 0
    else:
        improved = delta_percent > 0

    return {
        'arrow': '↑' if delta_percent > 0 else '↓',
        'percent': round(abs(delta_percent), 1),
        'direction_class': 'text-green-400' if improved else 'text-red-400'
    }


def _build_dashboard_data(query_args):
    """Build dashboard payload with filtering, sorting, pagination, and analytics."""
    dashboard_data = {
        'ml_available': ML_AVAILABLE,
        'metrics': None,
        'anomalies': [],
        'strategy_distribution': {'STRONG': 0, 'BALANCED': 0, 'FAST': 0},
        'file_type_distribution': {},
        'recent_uploads': [],
        'efficiency': {
            'avg_chunks_per_file': 0.0,
            'avg_overhead_percent': 0.0,
            'avg_entropy_gain': 0.0,
            'throughput_mb_s': 0.0
        },
        'algorithm_usage': [],
        'risk_strategy_correlation': {
            'high_risk_to_strong': 0.0,
            'safe_to_fast': 0.0,
            'medium_to_balanced': 0.0
        },
        'chunk_stats': {
            'avg_chunks': 0.0,
            'max_chunks': 0,
            'min_chunks': 0,
            'largest_file_name': 'N/A',
            'largest_file_size_mb': 0.0
        },
        'trends': {
            'encryption_time': {'arrow': '-', 'percent': 0.0, 'direction_class': 'text-gray-400'},
            'ml_confidence': {'arrow': '-', 'percent': 0.0, 'direction_class': 'text-gray-400'}
        },
        'filters': {
            'strategy': 'ALL',
            'risk': 'ALL',
            'sort_by': 'timestamp',
            'sort_dir': 'desc'
        },
        'pagination': {
            'page': 1,
            'per_page': 10,
            'total_rows': 0,
            'total_pages': 1,
            'start_row': 0,
            'end_row': 0,
            'has_prev': False,
            'has_next': False,
            'prev_page': 1,
            'next_page': 1
        },
        'system_health': {
            'model_status': 'Not Loaded',
            'security_scanner': 'Inactive',
            'anomaly_detector': 'Inactive',
            'total_files_processed': 0,
            'last_anomaly_time': 'N/A',
            'last_malware_detection': 'N/A',
            'model_last_trained': 'N/A',
            'key_generation_status': 'Not generated'
        }
    }

    if not ML_AVAILABLE:
        return dashboard_data

    strategy_filter = (query_args.get('strategy', 'ALL') or 'ALL').upper()
    risk_filter = (query_args.get('risk', 'ALL') or 'ALL').upper()
    sort_by = (query_args.get('sort_by', 'timestamp') or 'timestamp').lower()
    sort_dir = (query_args.get('sort_dir', 'desc') or 'desc').lower()
    page = query_args.get('page', 1, type=int)

    if sort_by not in {'timestamp', 'file_name', 'strategy', 'security_risk', 'encryption_time_ms', 'file_size_kb', 'num_chunks'}:
        sort_by = 'timestamp'
    if sort_dir not in {'asc', 'desc'}:
        sort_dir = 'desc'

    dashboard_data['filters'] = {
        'strategy': strategy_filter,
        'risk': risk_filter,
        'sort_by': sort_by,
        'sort_dir': sort_dir
    }

    chunk_map_payload = _load_chunk_map_data()
    chunk_history = chunk_map_payload.get('history', [])
    all_rows = _read_encryption_metrics_rows()

    dashboard_data['system_health']['total_files_processed'] = len(all_rows)

    # Core distributions from complete history.
    for row in all_rows:
        strategy = row.get('strategy', 'STRONG')
        if strategy in dashboard_data['strategy_distribution']:
            dashboard_data['strategy_distribution'][strategy] += 1
        file_type = row.get('file_type', 'unknown')
        dashboard_data['file_type_distribution'][file_type] = \
            dashboard_data['file_type_distribution'].get(file_type, 0) + 1

    # Filtering for table and panel drill-down.
    filtered_rows = all_rows
    if strategy_filter != 'ALL':
        filtered_rows = [r for r in filtered_rows if (r.get('strategy') or '').upper() == strategy_filter]
    if risk_filter != 'ALL':
        filtered_rows = [r for r in filtered_rows if (r.get('security_risk') or '').upper() == risk_filter]

    # Sorting.
    reverse = sort_dir == 'desc'
    if sort_by == 'timestamp':
        filtered_rows = sorted(filtered_rows, key=lambda r: r['timestamp_dt'], reverse=reverse)
    elif sort_by in {'encryption_time_ms', 'file_size_kb', 'num_chunks'}:
        filtered_rows = sorted(filtered_rows, key=lambda r: _safe_float(r.get(sort_by, 0)), reverse=reverse)
    elif sort_by == 'security_risk':
        rank = {'SAFE': 0, 'LOW_RISK': 1, 'MEDIUM_RISK': 2, 'HIGH_RISK': 3, 'BLOCKED': 4}
        filtered_rows = sorted(filtered_rows, key=lambda r: rank.get((r.get('security_risk') or '').upper(), 99), reverse=reverse)
    else:
        filtered_rows = sorted(filtered_rows, key=lambda r: str(r.get(sort_by, '')).lower(), reverse=reverse)

    # Pagination (10 rows/page)
    per_page = 10
    total_rows = len(filtered_rows)
    total_pages = max(1, math.ceil(total_rows / per_page))
    page = min(max(page, 1), total_pages)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    page_rows = filtered_rows[start_idx:end_idx]

    dashboard_data['pagination'] = {
        'page': page,
        'per_page': per_page,
        'total_rows': total_rows,
        'total_pages': total_pages,
        'start_row': start_idx + 1 if total_rows > 0 else 0,
        'end_row': min(end_idx, total_rows),
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'prev_page': page - 1 if page > 1 else 1,
        'next_page': page + 1 if page < total_pages else total_pages
    }

    # Recent uploads table rows with enriched columns.
    for row in page_rows:
        upload_id = _match_upload_id_for_metric(
            {
                'file_name': row.get('file_name', ''),
                'strategy': row.get('strategy', ''),
                'timestamp': row.get('timestamp_raw', '')
            },
            chunk_history
        )
        record = _find_chunk_record(chunk_history, upload_id) if upload_id else None
        strategy_source = 'ML'
        if record and record.get('strategy_source'):
            strategy_source = record['strategy_source']
        elif row.get('ml_confidence', 0) == 0:
            strategy_source = 'Default'

        dashboard_data['recent_uploads'].append({
            'timestamp': row.get('timestamp', 'N/A'),
            'file_name': row.get('file_name', 'Unknown'),
            'file_type': row.get('file_type', 'Unknown'),
            'strategy': row.get('strategy', 'N/A'),
            'encryption_time': f"{row.get('encryption_time_ms', 0):.1f}ms",
            'security_risk': row.get('security_risk', 'N/A'),
            'upload_id': upload_id,
            'size': f"{row.get('file_size_kb', 0):.2f} KB",
            'chunks': row.get('num_chunks', 0),
            'overhead': f"{row.get('storage_overhead_percent', 0):.1f}%",
            'integrity': 'OK' if row.get('success', True) else 'FAILED',
            'source': strategy_source
        })

    # Efficiency panel.
    if filtered_rows:
        avg_chunks = sum(r['num_chunks'] for r in filtered_rows) / len(filtered_rows)
        avg_overhead = sum(r['storage_overhead_percent'] for r in filtered_rows) / len(filtered_rows)
        avg_entropy_gain = sum((r['entropy_after'] - r['entropy_before']) for r in filtered_rows) / len(filtered_rows)
        total_size_mb = sum(r['file_size_kb'] for r in filtered_rows) / 1024
        total_time_s = sum(r['encryption_time_ms'] for r in filtered_rows) / 1000
        throughput_mb_s = (total_size_mb / total_time_s) if total_time_s > 0 else 0

        dashboard_data['efficiency'] = {
            'avg_chunks_per_file': round(avg_chunks, 1),
            'avg_overhead_percent': round(avg_overhead, 1),
            'avg_entropy_gain': round(avg_entropy_gain, 2),
            'throughput_mb_s': round(throughput_mb_s, 2)
        }

        # Chunk statistics panel.
        largest = max(filtered_rows, key=lambda r: r.get('file_size_kb', 0))
        dashboard_data['chunk_stats'] = {
            'avg_chunks': round(avg_chunks, 1),
            'max_chunks': max(r['num_chunks'] for r in filtered_rows),
            'min_chunks': min(r['num_chunks'] for r in filtered_rows),
            'largest_file_name': largest.get('file_name', 'N/A'),
            'largest_file_size_mb': round(largest.get('file_size_kb', 0) / 1024, 2)
        }

    # Algorithm usage panel from chunk-map records (filtered by current rows when possible).
    selected_upload_ids = set()
    for row in filtered_rows:
        upload_id = _match_upload_id_for_metric(
            {'file_name': row.get('file_name', ''), 'strategy': row.get('strategy', ''), 'timestamp': row.get('timestamp_raw', '')},
            chunk_history
        )
        if upload_id:
            selected_upload_ids.add(upload_id)

    algo_counts = {}
    for rec in chunk_history:
        if selected_upload_ids and rec.get('upload_id') not in selected_upload_ids:
            continue
        for chunk in rec.get('chunks', []):
            algo = chunk.get('algorithm', 'Unknown')
            algo_counts[algo] = algo_counts.get(algo, 0) + 1

    total_algo = sum(algo_counts.values())
    if total_algo > 0:
        dashboard_data['algorithm_usage'] = [
            {
                'algorithm': algo,
                'count': count,
                'percent': round((count / total_algo) * 100, 1)
            }
            for algo, count in sorted(algo_counts.items(), key=lambda item: item[1], reverse=True)
        ]

    # Risk vs strategy correlation.
    def _corr(risk, strategy):
        risk_rows = [r for r in all_rows if (r.get('security_risk') or '').upper() == risk]
        if not risk_rows:
            return 0.0
        match = [r for r in risk_rows if (r.get('strategy') or '').upper() == strategy]
        return round((len(match) / len(risk_rows)) * 100, 1)

    dashboard_data['risk_strategy_correlation'] = {
        'high_risk_to_strong': _corr('HIGH_RISK', 'STRONG'),
        'safe_to_fast': _corr('SAFE', 'FAST'),
        'medium_to_balanced': _corr('MEDIUM_RISK', 'BALANCED')
    }

    # Trends.
    dashboard_data['trends']['encryption_time'] = _calculate_trend(all_rows, 'encryption_time_ms', lower_is_better=True)
    dashboard_data['trends']['ml_confidence'] = _calculate_trend(all_rows, 'ml_confidence', lower_is_better=False)

    # Anomaly and posture details.
    alerts_file = config.DATA_DIR / 'logs' / 'anomaly_alerts.json'
    if alerts_file.exists():
        try:
            with open(alerts_file, 'r', encoding='utf-8') as f:
                all_alerts = json.load(f)
                normalized = []
                for alert in all_alerts[-10:]:
                    details = alert.get('details', {}) if isinstance(alert, dict) else {}
                    confidence = _safe_float(details.get('confidence', 0))
                    if confidence >= 0.85:
                        severity = 'HIGH'
                    elif confidence >= 0.7:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'

                    action = details.get('action', 'LOG_ALERT')
                    normalized.append({
                        'timestamp': alert.get('timestamp', ''),
                        'reason': details.get('reason', 'Unknown anomaly'),
                        'user_id': details.get('user_id', 'anonymous'),
                        'ip_address': details.get('ip_address', 'N/A'),
                        'confidence': confidence,
                        'severity': severity,
                        'file_name': details.get('file_name', 'N/A'),
                        'action': action,
                        'strategy_applied': 'STRONG' if action == 'FORCE_STRONG_ENCRYPTION' else 'N/A',
                        'mitigation': 'Enforce strong encryption and monitor' if action == 'FORCE_STRONG_ENCRYPTION' else 'Log and monitor'
                    })

                dashboard_data['anomalies'] = normalized[-5:]
                if normalized:
                    dashboard_data['system_health']['last_anomaly_time'] = normalized[-1].get('timestamp', '')[:16]
        except Exception as e:
            print(f"Error loading anomalies: {e}")

    risky_rows = [r for r in all_rows if (r.get('security_risk') or '').upper() in {'HIGH_RISK', 'MEDIUM_RISK'}]
    if risky_rows:
        last_risky = max(risky_rows, key=lambda r: r['timestamp_dt'])
        dashboard_data['system_health']['last_malware_detection'] = last_risky.get('timestamp', 'N/A')

    model_path = config.ML_MODEL_DIR / 'encryption_classifier.pkl'
    if model_path.exists():
        dashboard_data['system_health']['model_last_trained'] = datetime.fromtimestamp(model_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M')

    key_blob = config.RAW_DATA_FOLDER / 'store_in_me.enc'
    if key_blob.exists():
        dashboard_data['system_health']['key_generation_status'] = f"Ready ({datetime.fromtimestamp(key_blob.stat().st_mtime).strftime('%Y-%m-%d %H:%M')})"

    # Update core availability statuses.
    dashboard_data['system_health']['model_status'] = 'Active' if ml_classifier else 'Not Loaded'
    dashboard_data['system_health']['security_scanner'] = 'Active' if security_scanner else 'Inactive'
    dashboard_data['system_health']['anomaly_detector'] = 'Active' if anomaly_detector else 'Inactive'

    # Preserve existing summary stats payload.
    if performance_tracker:
        try:
            dashboard_data['metrics'] = performance_tracker.get_summary_stats()
        except Exception as e:
            print(f"Error loading metrics summary: {e}")

    return dashboard_data


def perform_security_scan(file_path):
    """
    Perform pre-upload security scan.
    
    Returns:
        Tuple of (scan_result, should_block, force_strong)
    """
    if not ML_AVAILABLE or security_scanner is None:
        return None, False, False
    
    try:
        scan_result = security_scanner.scan_file(file_path)
        return scan_result, scan_result['should_block'], scan_result['force_strong']
    except Exception as e:
        print(f"Security scan error: {e}")
        return None, False, False


def check_access_anomaly(ip_address, operation, file_name):
    """
    Check for anomalous access patterns.
    
    Returns:
        Tuple of (anomaly_result, should_force_strong)
    """
    if not ML_AVAILABLE or anomaly_detector is None:
        return None, False
    
    try:
        result = anomaly_detector.check_anomaly(
            user_id="anonymous",  # Could be enhanced with session-based user tracking
            ip_address=ip_address,
            operation=operation,
            file_name=file_name
        )
        # Force strong if anomaly detected with high confidence
        force_strong = result['is_anomaly'] and result['action'] == 'FORCE_STRONG_ENCRYPTION'
        return result, force_strong
    except Exception as e:
        print(f"Anomaly detection error: {e}")
        return None, False


def get_ml_encryption_strategy(file_path, user_override=None, force_strong=False):
    """
    Use ML to determine the optimal encryption strategy for a file.
    
    Args:
        file_path: Path to the uploaded file
        user_override: User's strategy choice ('ml', 'strong', 'balanced', 'fast')
        force_strong: Force STRONG due to security concerns
        
    Returns:
        Tuple of (EncryptionStrategy, classification_result)
    """
    normalized_override = (user_override or '').strip().lower()

    # Handle user override
    if normalized_override and normalized_override != 'ml':
        if normalized_override == 'strong':
            strategy = enc.EncryptionStrategy.STRONG
        elif normalized_override == 'balanced':
            strategy = enc.EncryptionStrategy.BALANCED
        elif normalized_override == 'fast':
            strategy = enc.EncryptionStrategy.FAST
        else:
            strategy = enc.EncryptionStrategy.STRONG
        
        # Still run ML for logging purposes
        ml_result = None
        if ML_AVAILABLE and ml_classifier:
            try:
                ml_result = ml_classifier.classify(file_path)
                ml_result['user_override'] = normalized_override
            except:
                pass
        return strategy, ml_result
    
    # Force STRONG if security concerns
    if force_strong:
        ml_result = None
        if ML_AVAILABLE and ml_classifier:
            try:
                ml_result = ml_classifier.classify(file_path)
                ml_result['force_strong'] = True
            except:
                pass
        return enc.EncryptionStrategy.STRONG, ml_result
    
    # Use ML classification
    if not ML_AVAILABLE or not config.ENABLE_ML_SELECTION:
        return enc.EncryptionStrategy.STRONG, None
    
    try:
        result = ml_classifier.classify(file_path)
        strategy = result['strategy']
        
        # Map ML strategy to encrypter strategy
        if strategy.value == 'STRONG':
            return enc.EncryptionStrategy.STRONG, result
        elif strategy.value == 'BALANCED':
            return enc.EncryptionStrategy.BALANCED, result
        elif strategy.value == 'FAST':
            return enc.EncryptionStrategy.FAST, result
        else:
            return enc.EncryptionStrategy.STRONG, result
            
    except Exception as e:
        print(f"ML classification error: {e}. Using default STRONG encryption.")
        return enc.EncryptionStrategy.STRONG, None


def start_encryption(strategy=None, ml_result=None, scan_result=None, anomaly_result=None, 
                     file_name="", file_size_kb=0, file_type="", strategy_source="ML Recommended"):
    """
    Start the encryption process with the specified strategy.
    
    Args:
        strategy: Encryption strategy to use (or None for default)
        ml_result: ML classification result for logging
        scan_result: Security scan result
        anomaly_result: Anomaly detection result
        file_name: Original file name
        file_size_kb: File size in KB
        file_type: File type/category
    """
    start_time = time.perf_counter()
    
    dv.divide()
    tools.empty_folder(str(config.UPLOAD_FOLDER))
    
    # Log ML decision if available
    if ml_result:
        print(f"ML Decision: {ml_result['security_level']} "
              f"(Confidence: {ml_result['confidence']*100:.1f}%)")
        print(f"Strategy: {ml_result['strategy'].value}")
        print(f"File Features: Size={ml_result['features']['size_kb']:.2f}KB, "
              f"Entropy={ml_result['features']['entropy']:.4f}, "
              f"Type={ml_result['features']['category']}")
    
    encrypt_result = enc.encrypter(strategy, strategy_source=strategy_source)
    
    # Calculate encryption time
    encryption_time_ms = (time.perf_counter() - start_time) * 1000
    
    # Count chunks
    num_chunks = len(tools.list_dir(str(config.ENCRYPTED_FOLDER)))
    upload_id = encrypt_result.get('upload_id') if isinstance(encrypt_result, dict) else None
    
    # Record metrics
    if ML_AVAILABLE and performance_tracker:
        try:
            performance_tracker.record_encryption(
                file_name=file_name,
                file_type=file_type or (ml_result['features']['category'] if ml_result else 'unknown'),
                file_size_kb=file_size_kb or (ml_result['features']['size_kb'] if ml_result else 0),
                strategy=strategy.value if strategy else 'STRONG',
                ml_confidence=ml_result['confidence'] if ml_result else 0,
                security_risk=scan_result['risk_level'] if scan_result else 'N/A',
                encryption_time_ms=encryption_time_ms,
                num_chunks=num_chunks,
                storage_overhead_percent=8.0,  # Approximate
                entropy_before=ml_result['features']['entropy'] if ml_result else 0,
                entropy_after=7.9  # Encrypted data is high entropy
            )
        except Exception as e:
            print(f"Metrics recording error: {e}")
    
    # Log access
    if ML_AVAILABLE and access_logger:
        try:
            access_logger.log_access(
                user_id="anonymous",
                ip_address=request.remote_addr if request else "127.0.0.1",
                operation="upload",
                file_name=file_name,
                file_size=int(file_size_kb * 1024),
                encryption_strategy=strategy.value if strategy else 'STRONG',
                success=True,
                duration_ms=int(encryption_time_ms)
            )
        except Exception as e:
            print(f"Access logging error: {e}")
    
    # Prepare ML info for template
    ml_info = None
    if ml_result:
        ml_info = {
            'security_level': ml_result['security_level'],
            'strategy': ml_result['strategy'].value,
            'confidence': f"{ml_result['confidence']*100:.1f}%",
            'size': f"{ml_result['features']['size_kb']:.2f} KB",
            'entropy': f"{ml_result['features']['entropy']:.4f}",
            'file_type': ml_result['features']['category'],
            'model_used': ml_result['model_used'],
            'user_override': ml_result.get('user_override'),
            'force_strong': ml_result.get('force_strong', False)
        }
    
    # Prepare security info for template
    security_info = None
    if scan_result:
        security_info = {
            'risk_level': scan_result['risk_level'],
            'findings': scan_result['findings'][:3],  # Show top 3 findings
            'force_strong': scan_result['force_strong']
        }
    
    # Prepare anomaly info
    anomaly_info = None
    if anomaly_result and anomaly_result.get('is_anomaly'):
        anomaly_info = {
            'detected': True,
            'confidence': f"{anomaly_result['confidence']*100:.1f}%",
            'reason': anomaly_result['reason']
        }
    
    # Performance info
    perf_info = {
        'encryption_time': f"{encryption_time_ms:.1f} ms",
        'num_chunks': num_chunks
    }
    
    return render_template('success.html', 
                          ml_info=ml_info, 
                          security_info=security_info,
                          anomaly_info=anomaly_info,
                          perf_info=perf_info,
                          upload_id=upload_id)


def start_decryption():
    dec.decrypter()
    tools.empty_folder(str(config.KEY_FOLDER))
    rst.restore()
    return render_template('restore_success.html')


@app.route('/return-key')
def return_key():
    print("reached")
    list_directory = tools.list_dir(str(config.KEY_FOLDER))
    if not list_directory:
        return "Error: No encryption key found. Please encrypt a file first.", 404
    filename = str(config.KEY_FOLDER / list_directory[0])
    print(filename)
    return send_file(filename, download_name="My_Key.pem", as_attachment=True)


@app.route('/return-file/')
def return_file():
    list_directory = tools.list_dir(str(config.RESTORED_FILES_FOLDER))
    if not list_directory:
        return "Error: No restored file found. Please try decrypting again.", 404
    filename = str(config.RESTORED_FILES_FOLDER / list_directory[0])
    print("****************************************")
    print(list_directory[0])
    print("****************************************")
    return send_file(filename, download_name=list_directory[0], as_attachment=True)


@app.route('/download/')
def downloads():
    return render_template('download.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/upload')
def call_page_upload():
    return render_template('upload.html')


@app.route('/home')
def back_home():
    tools.empty_folder(str(config.KEY_FOLDER))
    tools.empty_folder(str(config.RESTORED_FILES_FOLDER))
    return render_template('index.html')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/data', methods=['GET', 'POST'])
def upload_file():
    tools.empty_folder(str(config.UPLOAD_FOLDER))
    if request.method == 'GET':
        return render_template('upload.html')

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html', error='Please select a file to upload.')
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            return render_template('upload.html', error='No file selected. Please choose a file.')
        if file:
            filename = secure_filename(file.filename)
            file_path = str(config.UPLOAD_FOLDER / file.filename)
            file.save(file_path)
            
            # Get file info
            file_size_kb = os.path.getsize(file_path) / 1024
            file_ext = os.path.splitext(filename)[1].lower()
            
            print("\n" + "="*60)
            print("🔐 SECURE FILE UPLOAD PIPELINE")
            print("="*60)
            
            # ===== PHASE 1: Pre-Upload Security Scan =====
            print("\n📋 PHASE 1: Security Scan")
            print("-"*40)
            scan_result, should_block, scan_force_strong = perform_security_scan(file_path)
            
            if should_block:
                # Log the blocked attempt
                if ML_AVAILABLE and access_logger:
                    access_logger.log_access(
                        user_id="anonymous",
                        ip_address=request.remote_addr or "127.0.0.1",
                        operation="upload_blocked",
                        file_name=filename,
                        file_size=int(file_size_kb * 1024),
                        encryption_strategy="BLOCKED",
                        success=False,
                        duration_ms=0
                    )
                
                # Clean up the file
                tools.empty_folder(str(config.UPLOAD_FOLDER))
                
                risk_level = scan_result['risk_level'] if scan_result else 'HIGH'
                findings = scan_result['findings'][:3] if scan_result else ['Blocked by security policy']
                return render_template('upload.html', 
                    error=f"⚠️ File blocked due to security risk: {risk_level}. "
                          f"Findings: {', '.join(findings)}")
            
            if scan_result:
                print(f"  Risk Level: {scan_result['risk_level']}")
                print(f"  Findings: {len(scan_result['findings'])}")
                print(f"  Force Strong: {scan_force_strong}")
            else:
                print("  Scan: Skipped (ML not available)")
            
            # ===== PHASE 2: Anomaly Detection =====
            print("\n🔍 PHASE 2: Anomaly Detection")
            print("-"*40)
            anomaly_result, anomaly_force_strong = check_access_anomaly(
                ip_address=request.remote_addr or "127.0.0.1",
                operation="upload",
                file_name=filename
            )
            
            if anomaly_result:
                print(f"  Is Anomaly: {anomaly_result['is_anomaly']}")
                if anomaly_result['is_anomaly']:
                    print(f"  Reason: {anomaly_result['reason']}")
                    print(f"  Confidence: {anomaly_result['confidence']*100:.1f}%")
            else:
                print("  Anomaly Detection: Skipped (ML not available)")
            
            # ===== PHASE 3: Get User Override =====
            user_override = request.form.get('encryption_strategy', None)
            if user_override:
                user_override = user_override.strip().lower()

            if user_override in ('ml_recommended', 'ml', ''):
                user_override = None  # Let ML decide
            
            print(f"\n👤 User Override: {user_override or 'None (ML decides)'}")
            
            # ===== PHASE 4: ML-Based Strategy Selection =====
            print("\n🤖 PHASE 4: ML Strategy Selection")
            print("-"*40)
            
            # User-first policy: explicit user override bypasses force-strong escalation.
            security_force_strong = scan_force_strong or anomaly_force_strong
            user_override_selected = user_override in ('strong', 'balanced', 'fast')
            force_strong = security_force_strong and not user_override_selected

            if user_override_selected:
                strategy_source = 'User Override'
            elif force_strong:
                strategy_source = 'Forced by Security'
            else:
                strategy_source = 'ML Recommended'
            
            strategy, ml_result = get_ml_encryption_strategy(
                file_path, 
                user_override=user_override,
                force_strong=force_strong
            )
            
            if ml_result:
                print(f"  File: {filename}")
                print(f"  Security Level: {ml_result['security_level']}")
                print(f"  Strategy: {strategy.value}")
                print(f"  Confidence: {ml_result['confidence']*100:.1f}%")
                print(f"  Model: {ml_result['model_used']}")
                if force_strong:
                    print(f"  ⚠️ FORCED STRONG due to security/anomaly concerns")
                if user_override:
                    print(f"  👤 User override applied: {user_override}")
                if user_override_selected and security_force_strong:
                    print("  ℹ️ User-first policy active: security force-strong bypassed")
            else:
                print(f"  Using default encryption strategy: {strategy.value}")
            
            print("\n" + "="*60)
            print("🔒 Starting Encryption...")
            print("="*60 + "\n")
            
            # ===== PHASE 5: Encrypt with Metrics =====
            return start_encryption(
                strategy=strategy, 
                ml_result=ml_result,
                scan_result=scan_result,
                anomaly_result=anomaly_result,
                file_name=filename,
                file_size_kb=file_size_kb,
                file_type=file_ext,
                strategy_source=strategy_source
            )
        return render_template('upload.html', error='Invalid file format. Please upload a supported file.')

    return render_template('upload.html')


@app.route('/download_data', methods=['GET', 'POST'])
def upload_key():
    tools.empty_folder(str(config.KEY_FOLDER))
    if request.method == 'GET':
        return render_template('download.html')

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template('download.html', error='Please select your key file (.pem).')
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            return render_template('download.html', error='No key file selected. Please choose a .pem file.')
        if file and allowed_key_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(str(config.KEY_FOLDER / file.filename))
            return start_decryption()
        return render_template('download.html', error='Invalid key format. Please upload a .pem file.')

    return render_template('download.html')


@app.route('/dashboard')
def dashboard():
    dashboard_data = _build_dashboard_data(request.args)
    return render_template('dashboard.html', data=dashboard_data)


@app.route('/dashboard/export')
def dashboard_export():
    """Export dashboard analytics as CSV or JSON."""
    dashboard_data = _build_dashboard_data(request.args)
    export_format = (request.args.get('format', 'json') or 'json').lower()

    if export_format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'timestamp', 'file_name', 'file_type', 'strategy', 'security_risk',
            'encryption_time', 'size', 'chunks', 'overhead', 'source', 'integrity'
        ])
        for row in dashboard_data.get('recent_uploads', []):
            writer.writerow([
                row.get('timestamp', ''),
                row.get('file_name', ''),
                row.get('file_type', ''),
                row.get('strategy', ''),
                row.get('security_risk', ''),
                row.get('encryption_time', ''),
                row.get('size', ''),
                row.get('chunks', ''),
                row.get('overhead', ''),
                row.get('source', ''),
                row.get('integrity', '')
            ])

        mem = io.BytesIO(output.getvalue().encode('utf-8'))
        mem.seek(0)
        return send_file(
            mem,
            mimetype='text/csv',
            as_attachment=True,
            download_name='dashboard_analytics.csv'
        )

    payload = {
        'generated_at': datetime.now().isoformat(),
        'filters': dashboard_data.get('filters', {}),
        'summary': {
            'efficiency': dashboard_data.get('efficiency', {}),
            'algorithm_usage': dashboard_data.get('algorithm_usage', []),
            'risk_strategy_correlation': dashboard_data.get('risk_strategy_correlation', {}),
            'chunk_stats': dashboard_data.get('chunk_stats', {}),
            'trends': dashboard_data.get('trends', {}),
            'system_health': dashboard_data.get('system_health', {})
        },
        'rows': dashboard_data.get('recent_uploads', [])
    }
    return jsonify(payload)


@app.route('/encryption-details')
@app.route('/encryption-details/<upload_id>')
def encryption_details(upload_id=None):
    """Show chunk-level encryption details for latest or selected upload."""
    payload = _load_chunk_map_data()
    history = payload.get('history', [])

    if upload_id:
        record = _find_chunk_record(history, upload_id)
    else:
        upload_id = request.args.get('upload_id') or payload.get('latest_upload_id')
        record = _find_chunk_record(history, upload_id) if upload_id else payload.get('latest')

    if not record:
        return render_template('encryption_details.html',
                               record=None,
                               analysis=None,
                               message='No chunk encryption metadata found yet.')

    chunks = record.get('chunks', [])
    total_size_kb = round(sum(float(c.get('size_kb', 0)) for c in chunks), 2)
    avg_size_kb = round(total_size_kb / len(chunks), 2) if chunks else 0
    max_size_kb = round(max((float(c.get('size_kb', 0)) for c in chunks), default=0), 2)
    algorithms_used = sorted({c.get('algorithm', 'Unknown') for c in chunks})

    analysis = {
        'total_size_kb': total_size_kb,
        'avg_size_kb': avg_size_kb,
        'max_size_kb': max_size_kb,
        'algorithms_used': algorithms_used,
        'algorithm_count': len(algorithms_used)
    }

    return render_template('encryption_details.html',
                           record=record,
                           analysis=analysis,
                           message=None)


@app.route('/api/metrics')
def api_metrics():
    """API endpoint for metrics data (for AJAX/JS charts)."""
    if not ML_AVAILABLE or not performance_tracker:
        return jsonify({'error': 'ML not available'})
    
    try:
        stats = performance_tracker.get_summary_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)})


if __name__ == '__main__':
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
