/**
 * LAN SPY Frontend
 * Network device discovery and analysis
 */

// Global state
let lanSpyDevices = [];
let lanSpyScanRunning = false;
let lanSpyScanStatus = 'Ready';
let lanSpyEventSource = null;
let lanSpySelectedMac = null;

/**
 * Initialize LAN SPY mode
 */
function switchToLanSpy() {
    console.log('Switching to LAN SPY mode');
    
    // Load devices from backend
    refreshLanSpyDevices();
    
    // Connect to SSE stream
    connectToLanSpyEvents();
}

/**
 * Start network scan
 */
function startLanSpyScan() {
    const networkInput = document.getElementById('lanSpyNetworkInput');
    const network = networkInput.value.trim() || null;
    
    // Validate network if provided
    if (network && !isValidCIDR(network)) {
        showNotification('Invalid CIDR format. Use: 192.168.1.0/24', 'error');
        return;
    }
    
    console.log('Starting LAN SPY scan on network:', network || 'auto-detect');
    lanSpyScanRunning = true;
    
    // Show loader
    showLanSpyLoader('Initializing scan...', true);
    
    fetch('/lan_spy/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ network: network })
    })
    .then(r => r.json())
    .then(data => {
        console.log('Scan started:', data);
        lanSpyScanStatus = 'Scanning...';
    })
    .catch(err => {
        console.error('Scan error:', err);
        showNotification('Failed to start scan', 'error');
        hideLanSpyLoader();
        lanSpyScanRunning = false;
    });
}

/**
 * Stop network scan
 */
function stopLanSpyScan() {
    console.log('Stopping scan');
    
    fetch('/lan_spy/scan/stop', {
        method: 'POST'
    })
    .then(r => r.json())
    .then(data => {
        console.log('Scan stopped:', data);
        lanSpyScanRunning = false;
    })
    .catch(err => console.error('Stop error:', err));
}

/**
 * Refresh device list
 */
function refreshLanSpyDevices() {
    fetch('/lan_spy/devices')
        .then(r => r.json())
        .then(data => {
            lanSpyDevices = data.devices || [];
            renderLanSpyDeviceList();
            console.log('Loaded', lanSpyDevices.length, 'devices');
        })
        .catch(err => console.error('Refresh error:', err));
}

/**
 * Show non-blocking corner loader notification
 */
function showLanSpyLoader(message, show = true) {
    let loader = document.getElementById('lanSpyLoader');
    
    if (!loader) {
        // Create loader element
        loader = document.createElement('div');
        loader.id = 'lanSpyLoader';
        loader.className = 'lan-spy-loader';
        loader.innerHTML = `
            <div class="lan-spy-spinner-container">
                <div class="lan-spy-spinner"></div>
                <div>
                    <div class="lan-spy-loader-text" id="lanSpyLoaderText">Loading...</div>
                    <div class="lan-spy-loader-subtext" id="lanSpyLoaderSubtext">Devices: 0</div>
                </div>
            </div>
        `;
        document.body.appendChild(loader);
    }
    
    if (show) {
        document.getElementById('lanSpyLoaderText').textContent = message;
        loader.classList.add('visible');
        loader.classList.remove('hiding');
    } else {
        hideLanSpyLoader();
    }
}

/**
 * Update loader status in real-time
 */
function updateLanSpyLoader(message, deviceCount = null) {
    const loaderText = document.getElementById('lanSpyLoaderText');
    const loaderSubtext = document.getElementById('lanSpyLoaderSubtext');
    
    if (loaderText) {
        loaderText.textContent = message;
    }
    
    if (loaderSubtext && deviceCount !== null) {
        loaderSubtext.textContent = `Devices: ${deviceCount}`;
    }
}

/**
 * Hide loader with animation
 */
function hideLanSpyLoader() {
    const loader = document.getElementById('lanSpyLoader');
    if (loader) {
        loader.classList.add('hiding');
        setTimeout(() => {
            loader.classList.remove('visible');
            loader.classList.remove('hiding');
        }, 300);
    }
}

/**
 * Connect to SSE event stream
 */
function connectToLanSpyEvents() {
    if (lanSpyEventSource) {
        lanSpyEventSource.close();
    }
    
    lanSpyEventSource = new EventSource('/lan_spy/events');
    
    lanSpyEventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            
            switch (data.type) {
                case 'scan_start':
                    console.log('Scan started:', data);
                    showLanSpyLoader('Initializing scan...', true);
                    lanSpyScanRunning = true;
                    break;
                
                case 'scan_status':
                    lanSpyScanStatus = data.data.message;
                    updateLanSpyLoader(data.data.message, lanSpyDevices.length);
                    console.log('Status:', data.data.message);
                    break;
                
                case 'device_found':
                    lanSpyDevices.push(data.data);
                    renderLanSpyDeviceList();
                    updateLanSpyLoader(lanSpyScanStatus, lanSpyDevices.length);
                    console.log('Device found:', data.data);
                    break;
                
                case 'scan_complete':
                    lanSpyScanRunning = false;
                    hideLanSpyLoader();
                    console.log('Scan complete:', data.data);
                    showNotification(`Found ${data.data.devices_found} devices`, 'success');
                    break;
                
                case 'scan_error':
                    lanSpyScanRunning = false;
                    hideLanSpyLoader();
                    showNotification('Scan error: ' + data.data.message, 'error');
                    console.error('Scan error:', data.data);
                    break;
                
                case 'oui_update_complete':
                    showNotification('OUI database updated', 'success');
                    console.log('OUI updated:', data.data);
                    break;
            }
        } catch (e) {
            console.error('Event parsing error:', e);
        }
    };
    
    lanSpyEventSource.onerror = (err) => {
        console.error('SSE error:', err);
        lanSpyEventSource.close();
        
        // Reconnect after delay
        setTimeout(() => {
            console.log('Reconnecting to SSE stream...');
            connectToLanSpyEvents();
        }, 5000);
    };
}

/**
 * Render device list sidebar (deduplicated by MAC)
 */
function renderLanSpyDeviceList() {
    const listContainer = document.getElementById('lanSpyDeviceList');
    
    if (!lanSpyDevices || lanSpyDevices.length === 0) {
        listContainer.innerHTML = '<div class="lan-spy-empty-state"><p>🔍</p><p>No devices found</p><small>Start a scan to discover devices</small></div>';
        return;
    }
    
    // Deduplicate devices by MAC address (keep last occurrence)
    const uniqueDevices = {};
    lanSpyDevices.forEach(device => {
    const compositeKey = `${device.mac}-${device.internal_ip}`;
    uniqueDevices[compositeKey] = device;
});
    
    const deviceList = Object.values(uniqueDevices);
    
    // Sort by risk index (highest first)
    deviceList.sort((a, b) => (b.risk_index || 0) - (a.risk_index || 0));
    
    listContainer.innerHTML = deviceList.map(device => {
        const riskBadge = getRiskBadge(device.risk_index || 0);
        const isActive = lanSpySelectedMac === device.mac ? 'active' : '';
        const riskLevel = (device.risk_index || 0).toFixed(2);
        
        return `
            <div class="lan-spy-device-item ${isActive}" onclick="selectLanSpyDevice(event, '${device.mac}-${device.internal_ip}')">
                <div class="lan-spy-device-header">
                    <div class="lan-spy-device-primary">
                        ${device.hostname || device.internal_ip}
                    </div>
                    <div class="lan-spy-device-badge ${riskBadge}">
                        ${riskLevel}
                    </div>
                </div>
                <div class="lan-spy-device-secondary">
                    <span class="device-meta-ip">${device.internal_ip}</span>
                    <span class="device-meta-mfr">${device.mfr}</span>
                </div>
            </div>
        `;
    }).join('');
}

/**
 * Select device to view details
 */
/**
 * Select device to view details
 */
function selectLanSpyDevice(event, mac) { // Added event parameter
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    lanSpySelectedMac = mac;
    
    // Update active state
    document.querySelectorAll('.lan-spy-device-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Use event.currentTarget safely
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }
    
    displayLanSpyDeviceDetails(mac);
}

/**
 * Display selected device details
 */
function displayLanSpyDeviceDetails(mac) {
    const device = lanSpyDevices.find(d => `${d.mac}-${d.internal_ip}` === mac);
    
    if (!device) {
        console.error('Device not found:', mac);
        return;
    }
    
    const riskColor = getRiskColor(device.risk_index || 0);
    const riskBadge = getRiskBadge(device.risk_index || 0);
    
    const html = `
        <div class="lan-spy-detail-content">
            <!-- Subject Identity -->
            <div class="lan-spy-detail-section">
                <div class="lan-spy-detail-title">Subject Identity</div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">MAC Address</span>
                    <span class="lan-spy-detail-value">${device.mac}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Hostname</span>
                    <span class="lan-spy-detail-value">${device.hostname || 'N/A'}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Manufacturer</span>
                    <span class="lan-spy-detail-value">${device.mfr}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Device Class</span>
                    <span class="lan-spy-detail-value">${device.class}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Signal ID</span>
                    <span class="lan-spy-detail-value">${device.signal_id || 'N/A'}</span>
                </div>
            </div>
            
            <!-- Network Telemetry -->
            <div class="lan-spy-detail-section">
                <div class="lan-spy-detail-title">Network Telemetry</div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Internal IP</span>
                    <span class="lan-spy-detail-value">${device.internal_ip}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Bandwidth</span>
                    <span class="lan-spy-detail-value">${device.bandwidth_utilization}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Total Bytes</span>
                    <span class="lan-spy-detail-value">${device.bytes_total.toLocaleString()}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Current Flow (kbps)</span>
                    <span class="lan-spy-detail-value">${device.current_flow_kbps.toFixed(2)}</span>
                </div>
            </div>
            
            <!-- External Intelligence -->
            <div class="lan-spy-detail-section">
                <div class="lan-spy-detail-title">External Intelligence</div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Primary Uplink</span>
                    <span class="lan-spy-detail-value">${device.primary_uplink}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Destination Country</span>
                    <span class="lan-spy-detail-value">${device.destination_country}</span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Protocol</span>
                    <span class="lan-spy-detail-value">${device.protocol_detected}</span>
                </div>
            </div>
            
            <!-- Security Posture -->
            <div class="lan-spy-detail-section">
                <div class="lan-spy-detail-title">Security Posture</div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Risk Index</span>
                    <span class="lan-spy-risk-index ${riskBadge}">
                        ${(device.risk_index || 0).toFixed(2)} (${riskBadge.toUpperCase()})
                    </span>
                </div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Exposed Services</span>
                    <span class="lan-spy-detail-value">${Array.isArray(device.exposed_services) && device.exposed_services.length > 0 ? device.exposed_services.join(', ') : (device.exposed_services || 'None')}</span>
                </div>
                <div class="lan-spy-toggle">
                    <label>Tracking Device</label>
                    <input type="checkbox" ${device.tracking_device ? 'checked' : ''} 
                           onchange="toggleLanSpyFlag('${mac}', 'tracking', this.checked)">
                </div>
                <div class="lan-spy-toggle">
                    <label>Surveillance Device</label>
                    <input type="checkbox" ${device.surveillance_device ? 'checked' : ''} 
                           onchange="toggleLanSpyFlag('${mac}', 'surveillance', this.checked)">
                </div>
            </div>
            
            <!-- Timestamps -->
            <div class="lan-spy-detail-section">
                <div class="lan-spy-detail-title">Activity</div>
                <div class="lan-spy-detail-row">
                    <span class="lan-spy-detail-label">Last Seen</span>
                    <span class="lan-spy-detail-value">${new Date(device.last_seen).toLocaleString()}</span>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('lanSpyDetailCard').innerHTML = html;
}

/**
 * Toggle tracking or surveillance flag
 */
function toggleLanSpyFlag(mac, flagType, value) {
    const endpoint = flagType === 'tracking' ? 'tracking' : 'surveillance';
    
    fetch(`/lan_spy/device/${mac}/${endpoint}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ value: value })
    })
    .then(r => r.json())
    .then(data => {
        console.log('Flag updated:', data);
        
        // Update local device
        const device = lanSpyDevices.find(d => `${d.mac}-${d.internal_ip}` === mac);
        if (device) {
            if (flagType === 'tracking') {
                device.tracking_device = value;
            } else {
                device.surveillance_device = value;
            }
        }
        
        showNotification(`${flagType} device flag updated`, 'success');
    })
    .catch(err => {
        console.error('Flag update error:', err);
        showNotification('Failed to update flag', 'error');
    });
}

/**
 * Kill all running processes
 */
function killAllLanSpyProcesses() {
    if (!confirm('Are you sure you want to kill all LAN SPY processes?')) {
        return;
    }
    
    console.log('Killing all processes');
    stopLanSpyScan();
    showNotification('Processes terminated', 'info');
}

/**
 * Update OUI database
 */
function updateLanSpyOUI() {
    console.log('Updating OUI database');
    showLanSpyLoader('Downloading OUI database...', true);
    
    fetch('/lan_spy/oui/update', {
        method: 'POST'
    })
    .then(r => r.json())
    .then(data => {
        console.log('OUI update:', data);
        hideLanSpyLoader();
        if (data.status === 'success') {
            showNotification('OUI database updated successfully', 'success');
        } else {
            showNotification('OUI update failed: ' + data.message, 'error');
        }
    })
    .catch(err => {
        console.error('OUI update error:', err);
        hideLanSpyLoader();
        showNotification('Failed to update OUI database', 'error');
    });
}

/**
 * Get risk badge color (green/amber/red)
 */
function getRiskBadge(riskIndex) {
    if (riskIndex < 0.40) return 'green';
    if (riskIndex < 0.70) return 'amber';
    return 'red';
}

/**
 * Get risk color for styling
 */
function getRiskColor(riskIndex) {
    const badge = getRiskBadge(riskIndex);
    const colors = {
        'green': '#28a745',
        'amber': '#ffc107',
        'red': '#dc3545'
    };
    return colors[badge] || '#6c757d';
}

/**
 * Validate CIDR notation
 */
function isValidCIDR(cidr) {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    return cidrRegex.test(cidr);
}

/**
 * Show notification (using app's notification system)
 */
function showNotification(message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${message}`);
    
    // If app has notification system, use it
    if (window.showAppNotification) {
        window.showAppNotification(message, type);
    }
}

// Initialize when loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('LAN SPY module loaded');
});
