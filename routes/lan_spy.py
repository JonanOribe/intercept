"""
LAN SPY Routes
Flask blueprint for network scanning API and SSE event streaming.
"""

from flask import Blueprint, jsonify, request, Response
import logging
import threading
import queue
from datetime import datetime
import json
import time

from utils.lan_spy.scanner import NetworkScanner, update_oui_database, get_local_network
from utils.lan_spy.database import LANDatabase
from utils.lan_spy.risk_scoring import RiskScorer

logger = logging.getLogger('intercept.lan_spy.routes')

lan_spy_bp = Blueprint('lan_spy', __name__, url_prefix='/lan_spy')

# Global state
lan_spy_state = {
    'scanner': None,
    'database': None,
    'risk_scorer': None,
    'event_queue': queue.Queue(),
    'scan_running': False,
    'scan_worker_thread': None
}


def init_lan_spy_state():
    """Initialize LAN SPY state on app startup."""
    try:
        lan_spy_state['database'] = LANDatabase()
        lan_spy_state['risk_scorer'] = RiskScorer()
        
        # Auto-download OUI database if missing
        if not lan_spy_state['database']:
            logger.info("Updating OUI database...")
            result = update_oui_database()
            logger.info(f"OUI update: {result}")
        
        logger.info("LAN SPY state initialized")
    except Exception as e:
        logger.error(f"Error initializing LAN SPY: {e}")


def _emit_event(event_type: str, data: dict = None):
    """Queue event for SSE streaming."""
    event = {
        'type': event_type,
        'timestamp': datetime.now().isoformat() + 'Z',
        'data': data or {}
    }
    lan_spy_state['event_queue'].put(event)


def scan_worker(network: str = None):
    """Background worker thread for network scanning."""
    try:
        if network is None:
            network = get_local_network()
        
        _emit_event('scan_start', {'network': network, 'status': 'Initializing scan...'})
        
        # Create scanner
        scanner = NetworkScanner(network=network)
        lan_spy_state['scanner'] = scanner
        
        _emit_event('scan_status', {'message': 'Scanning network for active hosts...'})
        
        # Perform scan
        devices = scanner.scan()
        
        _emit_event('scan_status', {
            'message': f'Found {len(devices)} devices...' if devices else 'No devices found on this network'
        })
        
        # Store devices and calculate risk scores
        device_count = 0
        for device in devices:
            # Add to database
            lan_spy_state['database'].add_device(device)
            device_count += 1
            
            # Calculate risk score
            risk_data = lan_spy_state['risk_scorer'].calculate_risk(device)
            lan_spy_state['database'].add_risk_score(
                device['mac'],
                risk_data['hardware'],
                risk_data['exposure'],
                risk_data['external'],
                risk_data['traffic'],
                risk_data['total']
            )
            
            # Emit device found event
            device['risk_index'] = risk_data['total']
            device['risk_badge'] = risk_data['badge']
            _emit_event('device_found', device)
            
            _emit_event('scan_status', {
                'message': f'Processing device {device_count}/{len(devices)}: {device.get("hostname", device.get("internal_ip"))}'
            })
        
        # Record scan history
        elapsed = time.time() - scanner._start_time if hasattr(scanner, '_start_time') else 0
        lan_spy_state['database'].record_scan(network, len(devices), elapsed)
        
        # Emit completion
        _emit_event('scan_complete', {
            'devices_found': len(devices),
            'network': network
        })
        
    except Exception as e:
        logger.error(f"Scan worker error: {e}")
        _emit_event('scan_error', {'message': str(e)})
    finally:
        lan_spy_state['scan_running'] = False


@lan_spy_bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'service': 'lan_spy'}), 200


@lan_spy_bp.route('/devices', methods=['GET'])
def get_devices():
    """Get all discovered devices."""
    try:
        devices = lan_spy_state['database'].get_all_devices()
        
        # Add risk scores
        for device in devices:
            risk_data = lan_spy_state['database'].get_risk_score(device['mac'])
            if risk_data:
                device['risk_index'] = risk_data['total']
                device['risk_scores'] = {
                    'hardware': risk_data['hardware'],
                    'exposure': risk_data['exposure'],
                    'external': risk_data['external'],
                    'traffic': risk_data['traffic']
                }
            else:
                device['risk_index'] = 0.0
                device['risk_scores'] = {}
        
        return jsonify({'devices': devices, 'count': len(devices)}), 200
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return jsonify({'error': str(e)}), 500


@lan_spy_bp.route('/device/<mac>', methods=['GET'])
def get_device(mac):
    """Get specific device by MAC address."""
    try:
        device = lan_spy_state['database'].get_device(mac)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        # Add risk score
        risk_data = lan_spy_state['database'].get_risk_score(mac)
        if risk_data:
            device['risk_index'] = risk_data['total']
            device['risk_scores'] = {
                'hardware': risk_data['hardware'],
                'exposure': risk_data['exposure'],
                'external': risk_data['external'],
                'traffic': risk_data['traffic']
            }
        
        return jsonify(device), 200
    except Exception as e:
        logger.error(f"Error getting device: {e}")
        return jsonify({'error': str(e)}), 500


@lan_spy_bp.route('/scan', methods=['POST'])
def start_scan():
    """Start a network scan."""
    try:
        if lan_spy_state['scan_running']:
            return jsonify({'error': 'Scan already running'}), 409
        
        # Get network from request or auto-detect
        network = request.json.get('network') if request.json else None
        
        lan_spy_state['scan_running'] = True
        
        # Start scan in background thread
        thread = threading.Thread(target=scan_worker, args=(network,), daemon=True)
        lan_spy_state['scan_worker_thread'] = thread
        thread.start()
        
        return jsonify({'status': 'scan_started', 'network': network or get_local_network()}), 200
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        lan_spy_state['scan_running'] = False
        return jsonify({'error': str(e)}), 500


@lan_spy_bp.route('/scan/stop', methods=['POST'])
def stop_scan():
    """Stop the current scan."""
    try:
        if lan_spy_state['scanner']:
            lan_spy_state['scanner'].stop()
            _emit_event('scan_stopped', {'message': 'Scan stopped by user'})
        
        return jsonify({'status': 'scan_stopped'}), 200
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        return jsonify({'error': str(e)}), 500


@lan_spy_bp.route('/risk-score/<mac>', methods=['GET'])
def get_risk_score(mac):
    """Calculate risk score for a device."""
    try:
        device = lan_spy_state['database'].get_device(mac)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        risk_data = lan_spy_state['risk_scorer'].calculate_risk(device)
        return jsonify(risk_data), 200
    except Exception as e:
        logger.error(f"Error calculating risk score: {e}")
        return jsonify({'error': str(e)}), 500


@lan_spy_bp.route('/device/<mac>/tracking', methods=['POST'])
def toggle_tracking(mac):
    """Toggle tracking device flag."""
    try:
        value = request.json.get('value', True) if request.json else True
        lan_spy_state['database'].update_device_flag(mac, 'tracking_device', value)
        return jsonify({'status': 'updated', 'mac': mac, 'tracking_device': value}), 200
    except Exception as e:
        logger.error(f"Error updating tracking flag: {e}")
        return jsonify({'error': str(e)}), 500


@lan_spy_bp.route('/device/<mac>/surveillance', methods=['POST'])
def toggle_surveillance(mac):
    """Toggle surveillance device flag."""
    try:
        value = request.json.get('value', True) if request.json else True
        lan_spy_state['database'].update_device_flag(mac, 'surveillance_device', value)
        return jsonify({'status': 'updated', 'mac': mac, 'surveillance_device': value}), 200
    except Exception as e:
        logger.error(f"Error updating surveillance flag: {e}")
        return jsonify({'error': str(e)}), 500


@lan_spy_bp.route('/oui/update', methods=['POST'])
def update_oui():
    """Download and update OUI database."""
    try:
        _emit_event('oui_update_start', {'message': 'Downloading OUI database...'})
        result = update_oui_database()
        _emit_event('oui_update_complete', result)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error updating OUI: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@lan_spy_bp.route('/events', methods=['GET'])
def events():
    """SSE event stream for real-time updates."""
    def event_stream():
        while True:
            try:
                # Get next event with timeout
                event = lan_spy_state['event_queue'].get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # Keep connection alive
                yield ": keepalive\n\n"
            except Exception as e:
                logger.error(f"Event stream error: {e}")
                break
    
    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )
