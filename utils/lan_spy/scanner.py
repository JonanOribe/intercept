"""
Network Scanner for LAN SPY
Parallel network discovery with auto-detection and timeout enforcement.
"""

import logging
import subprocess
import socket
import os
import requests
from typing import Dict, List, Any, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import ipaddress
from datetime import datetime

logger = logging.getLogger('intercept.lan_spy.scanner')

OUI_PATH = 'instance/oui.txt'
OUI_URL = 'http://standards-oui.ieee.org/oui/oui.txt'

# Banned manufacturers per NDAA §889, FCC Covered List (2026)
BANNED_MANUFACTURERS = {
    'Hikvision', 'Hangzhou Hikvision Digital Technology',
    'Dahua', 'Zhejiang Dahua Technology',
    'Huawei', 'Huawei Technologies',
    'ZTE', 'Hytera', 'Hytera Communications',
    'DJI', 'Da-Jiang Innovations',
    'Autel Robotics', 'EZVIZ'
}

SUSPICIOUS_KEYWORDS = {'Tuya', 'Xiaomi', 'Anker'}

CRITICAL_PORTS = {
    23: 1.0,      # Telnet
    21: 0.7,      # FTP
    3389: 0.8,    # RDP
    48101: 0.7,   # Backdoor
    7547: 0.7     # TR-069
}


def get_local_network() -> str:
    """Auto-detect local network CIDR from host IP (e.g., 192.168.2.0/24)."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        logger.info(f"Detected local IP: {local_ip}")
        
        # Extract network prefix and assume /24 (common for home/office)
        parts = local_ip.split('.')
        if len(parts) == 4:
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            logger.info(f"Auto-detected network: {network}")
            return network
    except Exception as e:
        logger.warning(f"Failed to auto-detect network: {e}")
    
    # Fallback to common default
    return '192.168.1.0/24'


def get_oui_database() -> Dict[str, str]:
    """Load OUI (Organizationally Unique Identifier) database."""
    oui_dict = {}
    
    try:
        if not os.path.exists(OUI_PATH):
            logger.warning(f"OUI database not found at {OUI_PATH}")
            return oui_dict
        
        with open(OUI_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split('\t')
                if len(parts) >= 2:
                    mac_prefix = parts[0]
                    manufacturer = parts[1]
                    oui_dict[mac_prefix] = manufacturer
        
        logger.info(f"Loaded {len(oui_dict)} OUI entries")
    except Exception as e:
        logger.error(f"Error loading OUI database: {e}")
    
    return oui_dict


def update_oui_database() -> Dict[str, Any]:
    """Download and update OUI database from IEEE."""
    try:
        logger.info(f"Downloading OUI database from {OUI_URL}")
        
        response = requests.get(OUI_URL, timeout=30)
        response.raise_for_status()
        
        os.makedirs('instance', exist_ok=True)
        
        with open(OUI_PATH, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        count = len(response.text.split('\n'))
        logger.info(f"OUI database updated with {count} entries")
        
        return {
            'status': 'success',
            'message': f'OUI database updated with {count} entries',
            'entries_count': count
        }
    except Exception as e:
        logger.error(f"Error updating OUI database: {e}")
        return {
            'status': 'error',
            'message': f'Failed to update OUI database: {str(e)}'
        }


def get_manufacturer(mac: str) -> str:
    """Get manufacturer from MAC address using OUI lookup."""
    oui_dict = get_oui_database()
    
    # Normalize MAC
    mac_upper = mac.upper().replace(':', '').replace('-', '')
    
    # Try different prefix lengths (6, 5, 4, 3, 2 characters)
    for prefix_len in [6, 5, 4, 3, 2]:
        prefix = mac_upper[:prefix_len]
        if prefix in oui_dict:
            return oui_dict[prefix]
    
    return 'Unknown/Private'


class NetworkScanner:
    """LAN network scanner with parallel pinging and auto-detection."""
    
    def __init__(self, network: str = None):
        """Initialize scanner with optional network specification."""
        # Auto-detect network if not provided
        if not network or network == '192.168.1.0/24':
            network = get_local_network()
        
        self.network = network
        self.stop_flag = False
        self.oui_db = get_oui_database()
        self.max_workers = 64  # Parallel ping threads
        self.scan_timeout = 300  # 5 minute timeout
    
    def stop(self):
        """Stop the scan gracefully."""
        self.stop_flag = True
    
    def scan(self) -> List[Dict[str, Any]]:
        """Scan network with parallel pinging and 5-minute timeout."""
        devices = []
        start_time = time.time()
        
        try:
            logger.info(f"Starting network scan on {self.network} (timeout: {self.scan_timeout}s)")
            
            # Parse CIDR notation
            try:
                network_obj = ipaddress.ip_network(self.network, strict=False)
                ips = list(network_obj.hosts())
            except Exception as e:
                logger.error(f"Invalid network format: {e}")
                return devices
            
            logger.info(f"Scanning {len(ips)} addresses in {self.network} (parallel, {self.max_workers} workers)")
            
            # Parallel ping phase
            alive_ips = self._parallel_ping(ips, start_time)
            
            # Check timeout
            if time.time() - start_time > self.scan_timeout:
                logger.warning(f"Scan timeout exceeded ({self.scan_timeout}s)")
                return devices
            
            logger.info(f"Found {len(alive_ips)} alive hosts, gathering device details...")
            
            # Gather details for alive hosts
            for ip_str in alive_ips:
                if self.stop_flag or (time.time() - start_time > self.scan_timeout):
                    break
                
                try:
                    device = {
                        'signal_id': f"SIG-{len(devices):04d}-LAN",
                        'internal_ip': ip_str,
                        'mac': self._get_mac(ip_str),
                        'hostname': self._resolve_hostname(ip_str),
                        'mfr': self._get_manufacturer(ip_str),
                        'class': self._classify_device(ip_str),
                        'label': ip_str,
                        'bandwidth_utilization': 'Low',
                        'bytes_total': 0,
                        'current_flow_kbps': 0.0,
                        'primary_uplink': 'Unknown',
                        'destination_country': 'Unknown',
                        'protocol_detected': 'Unknown',
                        'risk_index': 0.0,
                        'exposed_services': [],
                        'tracking_device': False,
                        'surveillance_device': False,
                        'last_seen': self._get_timestamp()
                    }
                    
                    devices.append(device)
                    logger.debug(f"Found device: {ip_str} ({device['mfr']})")
                
                except Exception as e:
                    logger.error(f"Error processing host {ip_str}: {e}")
        
        except Exception as e:
            logger.error(f"Scan error: {e}")
        
        elapsed = time.time() - start_time
        logger.info(f"Scan complete: found {len(devices)} devices in {elapsed:.1f}s")
        return devices
    
    def _parallel_ping(self, ips: List[Any], start_time) -> List[str]:
        """Parallel ping all IPs with timeout enforcement."""
        alive_ips = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all ping tasks
            future_to_ip = {
                executor.submit(self._ping_host, str(ip)): str(ip) 
                for ip in ips
            }
            
            # Collect results with frequent timeout checks (5s intervals)
            for future in as_completed(future_to_ip, timeout=5):
                elapsed = time.time() - start_time
                if self.stop_flag or elapsed > self.scan_timeout:
                    logger.info(f"Scan timeout/stop at {elapsed:.1f}s")
                    executor.shutdown(wait=False)
                    break
                
                ip = future_to_ip[future]
                try:
                    if future.result(timeout=1):
                        alive_ips.append(ip)
                except Exception as e:
                    logger.debug(f"Error pinging {ip}: {e}")
        
        return alive_ips
    
    def _ping_host(self, ip: str) -> bool:
        """Ping host with 300ms timeout (very fast)."""
        try:
            param = '-n' if os.name == 'nt' else '-c'
            timeout_param = '-w' if os.name == 'nt' else '-W'
            
            if os.name == 'nt':
                cmd = ['ping', param, '1', timeout_param, '300', ip]
            else:
                cmd = ['ping', param, '1', timeout_param, '300', '-n', ip]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=1  # 1 second overall timeout
            )
            
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def _get_mac(self, ip: str) -> str:
        """Get MAC address via ARP with 1s timeout."""
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True,
                text=True,
                timeout=1
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part) == 17:
                            return part
        except (subprocess.TimeoutExpired, Exception):
            pass
        
        return '00:00:00:00:00:00'
    
    def _get_manufacturer(self, ip: str) -> str:
        """Get manufacturer from MAC address."""
        mac = self._get_mac(ip)
        return get_manufacturer(mac)
    
    def _classify_device(self, ip: str) -> str:
        """Classify device type."""
        return 'IoT / Embedded'
    
    def _resolve_hostname(self, ip: str) -> str:
        """Resolve hostname from IP with 1s timeout."""
        try:
            socket.setdefaulttimeout(1)
            hostname = socket.gethostbyaddr(ip)[0]
            socket.setdefaulttimeout(None)
            return hostname
        except (socket.herror, OSError, socket.timeout):
            socket.setdefaulttimeout(None)
            return ip
    
    def _get_timestamp(self) -> str:
        """Get ISO format timestamp."""
        return datetime.now().isoformat() + 'Z'
