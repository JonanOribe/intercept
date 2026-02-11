"""
LAN SPY Risk Scoring Module
4-factor algorithm for device risk assessment.
"""

import logging
from typing import Dict, Any
import yaml
import os

logger = logging.getLogger('intercept.lan_spy.risk_scoring')

# Default risk config (can be overridden by instance/risk_config.yaml)
DEFAULT_CONFIG = {
    'weights': {
        'hardware': 0.35,
        'exposure': 0.25,
        'external': 0.25,
        'traffic': 0.15
    },
    'banned_manufacturers': [
        'Hikvision', 'Hangzhou Hikvision Digital Technology',
        'Dahua', 'Zhejiang Dahua Technology',
        'Huawei', 'Huawei Technologies',
        'ZTE', 'Hytera', 'Hytera Communications',
        'DJI', 'Da-Jiang Innovations',
        'Autel Robotics', 'EZVIZ'
    ],
    'suspicious_keywords': ['Tuya', 'Xiaomi', 'Anker'],
    'high_risk_countries': {
        'CN': 1.0,  # China
        'RU': 0.9,  # Russia
        'IR': 0.9,  # Iran
        'KP': 1.0,  # North Korea
        'SY': 0.8   # Syria
    },
    'critical_ports': {
        23: 1.0,      # Telnet
        21: 0.7,      # FTP
        3389: 0.8,    # RDP
        48101: 0.7,   # Backdoor
        7547: 0.7     # TR-069
    }
}

RISK_CONFIG_PATH = 'instance/risk_config.yaml'


class RiskScorer:
    """Calculate device risk index (0.0 low to 1.0 critical)."""
    
    def __init__(self):
        """Initialize with configuration."""
        self.config = self._load_config()
        self.weights = self.config['weights']
        self.banned_manufacturers = set(self.config['banned_manufacturers'])
        self.suspicious_keywords = set(self.config['suspicious_keywords'])
        self.high_risk_countries = self.config['high_risk_countries']
        self.critical_ports = self.config['critical_ports']
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        try:
            if os.path.exists(RISK_CONFIG_PATH):
                with open(RISK_CONFIG_PATH, 'r') as f:
                    config = yaml.safe_load(f)
                    logger.info(f"Loaded risk config from {RISK_CONFIG_PATH}")
                    return config
        except Exception as e:
            logger.warning(f"Error loading risk config: {e}, using defaults")
        
        # Save default config for future editing
        try:
            os.makedirs('instance', exist_ok=True)
            with open(RISK_CONFIG_PATH, 'w') as f:
                yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
            logger.info(f"Saved default risk config to {RISK_CONFIG_PATH}")
        except Exception as e:
            logger.warning(f"Could not save default config: {e}")
        
        return DEFAULT_CONFIG
    
    def calculate_risk(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk index (0.0-1.0) for a device."""
        hardware_score = self._score_hardware(device)
        exposure_score = self._score_exposure(device)
        external_score = self._score_external(device)
        traffic_score = self._score_traffic(device)
        
        # Weighted total
        total_risk = (
            hardware_score * self.weights['hardware'] +
            exposure_score * self.weights['exposure'] +
            external_score * self.weights['external'] +
            traffic_score * self.weights['traffic']
        )
        
        # Manual overrides
        if device.get('tracking_device'):
            total_risk = max(total_risk, 0.7)  # Min 0.7 for tracking devices
        if device.get('surveillance_device'):
            total_risk = max(total_risk, 0.8)  # Min 0.8 for surveillance devices
        
        # Clamp to 0.0-1.0
        total_risk = max(0.0, min(1.0, total_risk))
        
        return {
            'hardware': round(hardware_score, 3),
            'exposure': round(exposure_score, 3),
            'external': round(external_score, 3),
            'traffic': round(traffic_score, 3),
            'total': round(total_risk, 3),
            'badge': self._get_badge(total_risk)
        }
    
    def _score_hardware(self, device: Dict[str, Any]) -> float:
        """Score based on manufacturer and device class."""
        score = 0.0
        mfr = device.get('mfr', '').lower()
        
        # Check banned manufacturers
        for banned in self.banned_manufacturers:
            if banned.lower() in mfr:
                return 1.0  # Maximum risk
        
        # Check suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword.lower() in mfr:
                score = max(score, 0.6)
        
        # Unknown/Private OUI
        if 'unknown' in mfr or 'private' in mfr:
            score = max(score, 0.7)
        
        # IoT/Embedded class bonus
        if 'IoT' in device.get('class', '') or 'Embedded' in device.get('class', ''):
            score = max(score, 0.4)
        
        return min(score, 1.0)
    
    def _score_exposure(self, device: Dict[str, Any]) -> float:
        """Score based on open ports and services."""
        exposed = device.get('exposed_services', [])
        score = 0.0
        
        if not exposed:
            return score
        
        for service in exposed:
            try:
                # Parse port from "port/protocol" format
                if '/' in str(service):
                    port = int(str(service).split('/')[0])
                else:
                    port = int(service)
                
                # Check against critical ports
                if port in self.critical_ports:
                    score = max(score, self.critical_ports[port])
            except (ValueError, IndexError):
                pass
        
        # Bonus for too many ports
        if len(exposed) > 5:
            score = max(score, 0.5)
        
        return min(score, 1.0)
    
    def _score_external(self, device: Dict[str, Any]) -> float:
        """Score based on external communication and ASN."""
        country = device.get('destination_country', '').upper()
        uplink = device.get('primary_uplink', '').lower()
        
        score = 0.0
        
        # Check high-risk countries
        if country in self.high_risk_countries:
            score = self.high_risk_countries[country]
        
        # Check suspicious ASN/org
        for keyword in self.suspicious_keywords:
            if keyword.lower() in uplink:
                score = max(score, 0.7)
        
        return min(score, 1.0)
    
    def _score_traffic(self, device: Dict[str, Any]) -> float:
        """Score based on traffic patterns and encryption."""
        bytes_total = device.get('bytes_total', 0)
        protocol = device.get('protocol_detected', '').lower()
        
        score = 0.0
        
        # High external bandwidth anomaly
        if bytes_total > 10000000:  # >10MB
            score = max(score, 0.6)
        
        # Suspicious unencrypted protocols
        if 'mqtt' in protocol and 'tls' not in protocol:
            score = max(score, 0.7)
        
        if 'http' in protocol and 'https' not in protocol:
            score = max(score, 0.5)
        
        return min(score, 1.0)
    
    def _get_badge(self, risk_index: float) -> str:
        """Get badge color based on risk level."""
        if risk_index < 0.40:
            return 'green'
        elif risk_index < 0.70:
            return 'amber'
        else:
            return 'red'
    
    def get_badge_color_hex(self, badge: str) -> str:
        """Get hex color for badge."""
        colors = {
            'green': '#28a745',
            'amber': '#ffc107',
            'red': '#dc3545'
        }
        return colors.get(badge, '#6c757d')
