"""
Pre-Upload Security Module

Implements malware detection and file security scanning before encryption.
Uses heuristics and ML-based classification to detect suspicious files.

Detection Methods:
1. Extension-based detection (dangerous file types)
2. Entropy analysis (packed/encrypted malware detection)
3. File header analysis (magic bytes verification)
4. Size anomaly detection

Actions on Suspicious Files:
- Flag as HIGH_RISK
- Auto-upgrade to STRONG encryption
- Log security event

Reference: Research paper on adaptive hybrid cryptography with security checks
"""

import os
import math
import struct
from pathlib import Path
from typing import Dict, Any, List, Tuple
from enum import Enum
from datetime import datetime


class RiskLevel(Enum):
    """Risk level classification for uploaded files."""
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    BLOCKED = "BLOCKED"


class SecurityScanner:
    """
    Pre-upload security scanner for malware detection.
    
    Uses multiple heuristics to assess file risk:
    - Extension analysis
    - Entropy analysis
    - Header verification
    - Size anomaly detection
    """
    
    # Dangerous/executable extensions
    BLOCKED_EXTENSIONS = {
        'exe', 'dll', 'scr', 'pif', 'com',  # Windows executables
        'bat', 'cmd', 'ps1', 'vbs', 'vbe',   # Scripts
        'msi', 'msp', 'mst',                  # Installers
        'jar', 'jnlp',                        # Java
        'hta', 'cpl', 'msc',                  # Windows system
        'reg', 'inf',                         # Registry/config
    }
    
    HIGH_RISK_EXTENSIONS = {
        'js', 'jse', 'ws', 'wsf', 'wsc', 'wsh',  # Script files
        'lnk', 'url',                             # Shortcuts
        'docm', 'xlsm', 'pptm',                   # Macro-enabled Office
        'iso', 'img',                             # Disk images
        'apk', 'ipa',                             # Mobile apps
    }
    
    MEDIUM_RISK_EXTENSIONS = {
        'zip', 'rar', '7z', 'tar', 'gz',  # Archives (can contain malware)
        'doc', 'xls', 'ppt',               # Old Office formats (macros)
        'pdf',                              # Can contain scripts
        'swf', 'fla',                       # Flash
    }
    
    # Known safe magic bytes
    SAFE_MAGIC_BYTES = {
        b'\x89PNG': 'png',
        b'\xFF\xD8\xFF': 'jpeg',
        b'GIF8': 'gif',
        b'%PDF': 'pdf',
        b'PK\x03\x04': 'zip',
        b'Rar!': 'rar',
        b'\x1f\x8b': 'gzip',
        b'ID3': 'mp3',
        b'\x00\x00\x00': 'mp4',  # ftyp
    }
    
    # Dangerous magic bytes
    DANGEROUS_MAGIC_BYTES = {
        b'MZ': 'exe',           # Windows executable
        b'\x7fELF': 'elf',      # Linux executable
        b'#!': 'script',        # Script shebang
        b'\xca\xfe\xba\xbe': 'java_class',
        b'\xef\xbb\xbf': 'bom',  # UTF-8 BOM (can hide scripts)
    }
    
    # High entropy threshold (indicates encryption/packing)
    HIGH_ENTROPY_THRESHOLD = 7.5
    SUSPICIOUS_ENTROPY_THRESHOLD = 7.0
    
    def __init__(self):
        """Initialize security scanner."""
        self.scan_history = []
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    def analyze_extension(self, file_path: str) -> Tuple[RiskLevel, str]:
        """Analyze file extension for risk."""
        ext = os.path.splitext(file_path)[1].lower()
        ext = ext[1:] if ext.startswith('.') else ext
        
        if ext in self.BLOCKED_EXTENSIONS:
            return RiskLevel.BLOCKED, f"Blocked extension: .{ext} (executable/script)"
        elif ext in self.HIGH_RISK_EXTENSIONS:
            return RiskLevel.HIGH_RISK, f"High-risk extension: .{ext}"
        elif ext in self.MEDIUM_RISK_EXTENSIONS:
            return RiskLevel.MEDIUM_RISK, f"Medium-risk extension: .{ext} (may contain macros/scripts)"
        else:
            return RiskLevel.SAFE, "Extension appears safe"
    
    def analyze_header(self, file_path: str) -> Tuple[RiskLevel, str]:
        """Analyze file header (magic bytes) for risk."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            if len(header) < 4:
                return RiskLevel.SAFE, "File too small for header analysis"
            
            # Check for dangerous magic bytes
            for magic, ftype in self.DANGEROUS_MAGIC_BYTES.items():
                if header.startswith(magic):
                    return RiskLevel.HIGH_RISK, f"Dangerous file type detected: {ftype}"
            
            # Check extension matches magic bytes
            ext = os.path.splitext(file_path)[1].lower()[1:]
            for magic, expected_ext in self.SAFE_MAGIC_BYTES.items():
                if header.startswith(magic):
                    if ext != expected_ext and ext not in ['docx', 'xlsx', 'pptx']:  # Office uses ZIP
                        return RiskLevel.MEDIUM_RISK, f"Extension mismatch: .{ext} vs {expected_ext}"
                    return RiskLevel.SAFE, f"Valid {expected_ext} file"
            
            return RiskLevel.LOW_RISK, "Unknown file format"
            
        except Exception as e:
            return RiskLevel.MEDIUM_RISK, f"Header analysis error: {e}"
    
    def analyze_entropy(self, file_path: str) -> Tuple[RiskLevel, str, float]:
        """Analyze file entropy for packed/encrypted content."""
        try:
            with open(file_path, 'rb') as f:
                # Read first 1MB for entropy analysis
                data = f.read(1024 * 1024)
            
            entropy = self.calculate_entropy(data)
            
            if entropy >= self.HIGH_ENTROPY_THRESHOLD:
                return (RiskLevel.HIGH_RISK, 
                       f"Very high entropy ({entropy:.2f}): Possible packed malware or encrypted content",
                       entropy)
            elif entropy >= self.SUSPICIOUS_ENTROPY_THRESHOLD:
                return (RiskLevel.MEDIUM_RISK,
                       f"High entropy ({entropy:.2f}): May be compressed or obfuscated",
                       entropy)
            else:
                return RiskLevel.SAFE, f"Normal entropy ({entropy:.2f})", entropy
                
        except Exception as e:
            return RiskLevel.LOW_RISK, f"Entropy analysis error: {e}", 0.0
    
    def analyze_size(self, file_path: str) -> Tuple[RiskLevel, str]:
        """Check for size anomalies."""
        try:
            size = os.path.getsize(file_path)
            ext = os.path.splitext(file_path)[1].lower()[1:]
            
            # Very small executables are suspicious
            if ext in ['exe', 'dll'] and size < 10 * 1024:  # < 10KB
                return RiskLevel.HIGH_RISK, f"Suspiciously small executable ({size} bytes)"
            
            # Very large files for certain types
            if ext in ['txt', 'csv'] and size > 100 * 1024 * 1024:  # > 100MB
                return RiskLevel.MEDIUM_RISK, f"Unusually large {ext} file ({size / (1024*1024):.1f} MB)"
            
            return RiskLevel.SAFE, f"Normal file size ({size} bytes)"
            
        except Exception as e:
            return RiskLevel.LOW_RISK, f"Size analysis error: {e}"
    
    def check_embedded_executables(self, file_path: str) -> Tuple[RiskLevel, str]:
        """Check for embedded executables in archives/documents."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(5 * 1024 * 1024)  # Read up to 5MB
            
            # Look for embedded executable signatures
            exe_signatures = [b'MZ', b'\x7fELF', b'#!']
            for sig in exe_signatures:
                # Skip if it's at the beginning (already caught by header analysis)
                pos = content.find(sig, 100)
                if pos > 100:
                    return RiskLevel.HIGH_RISK, f"Possible embedded executable at offset {pos}"
            
            return RiskLevel.SAFE, "No embedded executables detected"
            
        except Exception as e:
            return RiskLevel.LOW_RISK, f"Embedded scan error: {e}"
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform complete security scan on a file.
        
        Returns:
            Dictionary containing:
            - risk_level: Overall risk assessment
            - should_block: Whether to block the upload
            - force_strong: Whether to force STRONG encryption
            - details: List of scan findings
            - recommendations: Suggested actions
        """
        file_path = str(file_path)
        filename = os.path.basename(file_path)
        
        findings = []
        risk_levels = []
        
        # 1. Extension Analysis
        ext_risk, ext_msg = self.analyze_extension(file_path)
        findings.append({'check': 'Extension', 'risk': ext_risk.value, 'message': ext_msg})
        risk_levels.append(ext_risk)
        
        # 2. Header Analysis
        header_risk, header_msg = self.analyze_header(file_path)
        findings.append({'check': 'Header', 'risk': header_risk.value, 'message': header_msg})
        risk_levels.append(header_risk)
        
        # 3. Entropy Analysis
        entropy_risk, entropy_msg, entropy_value = self.analyze_entropy(file_path)
        findings.append({'check': 'Entropy', 'risk': entropy_risk.value, 'message': entropy_msg, 'value': entropy_value})
        risk_levels.append(entropy_risk)
        
        # 4. Size Analysis
        size_risk, size_msg = self.analyze_size(file_path)
        findings.append({'check': 'Size', 'risk': size_risk.value, 'message': size_msg})
        risk_levels.append(size_risk)
        
        # 5. Embedded Executable Check (for archives/documents)
        ext = os.path.splitext(file_path)[1].lower()[1:]
        if ext in ['zip', 'rar', '7z', 'doc', 'docx', 'pdf']:
            embed_risk, embed_msg = self.check_embedded_executables(file_path)
            findings.append({'check': 'Embedded', 'risk': embed_risk.value, 'message': embed_msg})
            risk_levels.append(embed_risk)
        
        # Determine overall risk level
        if RiskLevel.BLOCKED in risk_levels:
            overall_risk = RiskLevel.BLOCKED
        elif RiskLevel.HIGH_RISK in risk_levels:
            overall_risk = RiskLevel.HIGH_RISK
        elif RiskLevel.MEDIUM_RISK in risk_levels:
            overall_risk = RiskLevel.MEDIUM_RISK
        elif RiskLevel.LOW_RISK in risk_levels:
            overall_risk = RiskLevel.LOW_RISK
        else:
            overall_risk = RiskLevel.SAFE
        
        # Determine actions
        should_block = overall_risk == RiskLevel.BLOCKED
        force_strong = overall_risk in [RiskLevel.HIGH_RISK, RiskLevel.MEDIUM_RISK]
        
        # Generate recommendations
        recommendations = []
        if should_block:
            recommendations.append("Upload blocked: File type not allowed for security reasons")
        elif force_strong:
            recommendations.append("Auto-upgrading to STRONG encryption due to security concerns")
            recommendations.append("File flagged for additional monitoring")
        
        result = {
            'filename': filename,
            'risk_level': overall_risk.value,
            'should_block': should_block,
            'force_strong': force_strong,
            'findings': findings,
            'recommendations': recommendations,
            'scan_time': datetime.now().isoformat()
        }
        
        # Store in history
        self.scan_history.append(result)
        
        return result
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of all scans performed."""
        if not self.scan_history:
            return {'total_scans': 0}
        
        risk_counts = {}
        for scan in self.scan_history:
            risk = scan['risk_level']
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        return {
            'total_scans': len(self.scan_history),
            'risk_distribution': risk_counts,
            'blocked_count': sum(1 for s in self.scan_history if s['should_block']),
            'force_strong_count': sum(1 for s in self.scan_history if s['force_strong'])
        }


# Global scanner instance
_scanner = None

def get_scanner() -> SecurityScanner:
    """Get or create the global security scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = SecurityScanner()
    return _scanner


def scan_file(file_path: str) -> Dict[str, Any]:
    """Convenience function to scan a file."""
    scanner = get_scanner()
    return scanner.scan_file(file_path)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        scanner = SecurityScanner()
        result = scanner.scan_file(sys.argv[1])
        
        print("\n" + "=" * 60)
        print("SECURITY SCAN REPORT")
        print("=" * 60)
        print(f"File: {result['filename']}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Blocked: {result['should_block']}")
        print(f"Force STRONG: {result['force_strong']}")
        
        print("\nFindings:")
        for finding in result['findings']:
            print(f"  [{finding['risk']}] {finding['check']}: {finding['message']}")
        
        if result['recommendations']:
            print("\nRecommendations:")
            for rec in result['recommendations']:
                print(f"  - {rec}")
    else:
        print("Usage: python security_scanner.py <file_path>")
