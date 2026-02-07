"""
LAN SPY Database Module
SQLite persistence for discovered devices and scan history.
"""

import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import os

logger = logging.getLogger('intercept.lan_spy.database')

DB_PATH = 'instance/lan_devices.db'


class LANDatabase:
    """SQLite database for LAN SPY device storage."""
    
    def __init__(self):
        """Initialize database and create schema if needed."""
        os.makedirs('instance', exist_ok=True)
        self.db_path = DB_PATH
        self._init_schema()
    
    def _init_schema(self):
        """Create database tables if they don't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Devices table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT UNIQUE NOT NULL,
                    ip TEXT,
                    hostname TEXT,
                    manufacturer TEXT,
                    device_class TEXT,
                    label TEXT,
                    bandwidth_utilization TEXT,
                    bytes_total INTEGER DEFAULT 0,
                    current_flow_kbps REAL DEFAULT 0.0,
                    primary_uplink TEXT,
                    destination_country TEXT,
                    protocol_detected TEXT,
                    exposed_services TEXT,
                    tracking_device INTEGER DEFAULT 0,
                    surveillance_device INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT
                )
            ''')
            
            # Scan history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp TEXT NOT NULL,
                    network_scanned TEXT,
                    devices_found INTEGER,
                    scan_duration_seconds REAL,
                    scan_status TEXT
                )
            ''')
            
            # Risk scores table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS risk_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT UNIQUE NOT NULL,
                    hardware_score REAL DEFAULT 0.0,
                    exposure_score REAL DEFAULT 0.0,
                    external_score REAL DEFAULT 0.0,
                    traffic_score REAL DEFAULT 0.0,
                    total_risk_index REAL DEFAULT 0.0,
                    last_calculated TEXT,
                    FOREIGN KEY (mac) REFERENCES devices(mac)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Error initializing database schema: {e}")
    
    def add_device(self, device: Dict[str, Any]) -> bool:
        """Add or update a device in the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            now = datetime.now().isoformat() + 'Z'
            
            # Check if device exists
            cursor.execute('SELECT id FROM devices WHERE mac = ?', (device['mac'],))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing device
                cursor.execute('''
                    UPDATE devices SET
                        ip = ?, hostname = ?, manufacturer = ?,
                        device_class = ?, label = ?, bandwidth_utilization = ?,
                        bytes_total = ?, current_flow_kbps = ?,
                        primary_uplink = ?, destination_country = ?,
                        protocol_detected = ?, exposed_services = ?,
                        last_seen = ?
                    WHERE mac = ?
                ''', (
                    device.get('internal_ip'), device.get('hostname'),
                    device.get('mfr'), device.get('class'),
                    device.get('label'), device.get('bandwidth_utilization'),
                    device.get('bytes_total', 0), device.get('current_flow_kbps', 0.0),
                    device.get('primary_uplink'), device.get('destination_country'),
                    device.get('protocol_detected'), str(device.get('exposed_services', [])),
                    now, device['mac']
                ))
            else:
                # Insert new device
                cursor.execute('''
                    INSERT INTO devices (
                        mac, ip, hostname, manufacturer, device_class,
                        label, bandwidth_utilization, bytes_total,
                        current_flow_kbps, primary_uplink, destination_country,
                        protocol_detected, exposed_services, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device['mac'], device.get('internal_ip'), device.get('hostname'),
                    device.get('mfr'), device.get('class'), device.get('label'),
                    device.get('bandwidth_utilization'), device.get('bytes_total', 0),
                    device.get('current_flow_kbps', 0.0), device.get('primary_uplink'),
                    device.get('destination_country'), device.get('protocol_detected'),
                    str(device.get('exposed_services', [])), now, now
                ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error adding device {device.get('mac')}: {e}")
            return False
    
    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Retrieve all devices from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT mac, ip, hostname, manufacturer, device_class,
                       label, bandwidth_utilization, bytes_total,
                       current_flow_kbps, primary_uplink, destination_country,
                       protocol_detected, exposed_services, tracking_device,
                       surveillance_device, first_seen, last_seen
                FROM devices
            ''')
            
            devices = []
            for row in cursor.fetchall():
                devices.append({
                    'mac': row[0],
                    'internal_ip': row[1],
                    'hostname': row[2],
                    'mfr': row[3],
                    'class': row[4],
                    'label': row[5],
                    'bandwidth_utilization': row[6],
                    'bytes_total': row[7],
                    'current_flow_kbps': row[8],
                    'primary_uplink': row[9],
                    'destination_country': row[10],
                    'protocol_detected': row[11],
                    'exposed_services': row[12],
                    'tracking_device': bool(row[13]),
                    'surveillance_device': bool(row[14]),
                    'first_seen': row[15],
                    'last_seen': row[16]
                })
            
            conn.close()
            return devices
        except Exception as e:
            logger.error(f"Error retrieving devices: {e}")
            return []
    
    def get_device(self, mac: str) -> Optional[Dict[str, Any]]:
        """Get a specific device by MAC address."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT mac, ip, hostname, manufacturer, device_class,
                       label, bandwidth_utilization, bytes_total,
                       current_flow_kbps, primary_uplink, destination_country,
                       protocol_detected, exposed_services, tracking_device,
                       surveillance_device, first_seen, last_seen
                FROM devices WHERE mac = ?
            ''', (mac,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'mac': row[0],
                    'internal_ip': row[1],
                    'hostname': row[2],
                    'mfr': row[3],
                    'class': row[4],
                    'label': row[5],
                    'bandwidth_utilization': row[6],
                    'bytes_total': row[7],
                    'current_flow_kbps': row[8],
                    'primary_uplink': row[9],
                    'destination_country': row[10],
                    'protocol_detected': row[11],
                    'exposed_services': row[12],
                    'tracking_device': bool(row[13]),
                    'surveillance_device': bool(row[14]),
                    'first_seen': row[15],
                    'last_seen': row[16]
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving device {mac}: {e}")
            return None
    
    def update_device_flag(self, mac: str, flag_name: str, value: bool) -> bool:
        """Update tracking or surveillance device flag."""
        try:
            if flag_name not in ['tracking_device', 'surveillance_device']:
                return False
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = f'UPDATE devices SET {flag_name} = ? WHERE mac = ?'
            cursor.execute(query, (int(value), mac))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error updating device flag: {e}")
            return False
    
    def record_scan(self, network: str, devices_found: int, duration: float) -> bool:
        """Record scan history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            now = datetime.now().isoformat() + 'Z'
            
            cursor.execute('''
                INSERT INTO scan_history (
                    scan_timestamp, network_scanned, devices_found,
                    scan_duration_seconds, scan_status
                ) VALUES (?, ?, ?, ?, ?)
            ''', (now, network, devices_found, duration, 'completed'))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error recording scan: {e}")
            return False
    
    def add_risk_score(self, mac: str, hardware: float, exposure: float,
                       external: float, traffic: float, total: float) -> bool:
        """Add or update risk score for a device."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            now = datetime.now().isoformat() + 'Z'
            
            cursor.execute('SELECT id FROM risk_scores WHERE mac = ?', (mac,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute('''
                    UPDATE risk_scores SET
                        hardware_score = ?, exposure_score = ?,
                        external_score = ?, traffic_score = ?,
                        total_risk_index = ?, last_calculated = ?
                    WHERE mac = ?
                ''', (hardware, exposure, external, traffic, total, now, mac))
            else:
                cursor.execute('''
                    INSERT INTO risk_scores (
                        mac, hardware_score, exposure_score,
                        external_score, traffic_score, total_risk_index,
                        last_calculated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (mac, hardware, exposure, external, traffic, total, now))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error adding risk score: {e}")
            return False
    
    def get_risk_score(self, mac: str) -> Optional[Dict[str, float]]:
        """Get risk score for a device."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT hardware_score, exposure_score, external_score,
                       traffic_score, total_risk_index, last_calculated
                FROM risk_scores WHERE mac = ?
            ''', (mac,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'hardware': row[0],
                    'exposure': row[1],
                    'external': row[2],
                    'traffic': row[3],
                    'total': row[4],
                    'last_calculated': row[5]
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving risk score: {e}")
            return None
    
    def clear_devices(self) -> bool:
        """Clear all devices from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM devices')
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error clearing devices: {e}")
            return False
