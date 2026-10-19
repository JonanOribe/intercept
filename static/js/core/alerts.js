const AlertCenter = (function() {
    'use strict';

    const TRACKER_RULE_NAME = 'Tracker Detected';

    const DELIVERY_LABELS = {
        sent: 'pushed',
        rate_limited: 'held back: hourly limit',
        quiet_hours: 'held back: quiet hours',
        no_channel: 'no push channel',
        off: 'push off for this rule',
    };

    const WATCHLIST_HINTS = {
        aircraft: 'ICAO hex, registration or callsign (ADS-B, ACARS, VDL2)',
        vessel: 'MMSI, ship name or callsign (AIS, DSC)',
        callsign: 'LY1ABC (any SSID) or LY1ABC-9 (that SSID only) (APRS, Meshtastic)',
        device: 'MAC address or BSSID (WiFi, Bluetooth, TSCM)',
        frequency: '162.025 (MHz), 162025 kHz, or a range 144-146',
        keyword: 'A word or phrase, not case sensitive (pager, ACARS, APRS text)',
    };

    const CHANNEL_FIELDS = {
        ntfy: [
            { key: 'server', label: 'Server', placeholder: 'https://ntfy.sh' },
            { key: 'topic', label: 'Topic', placeholder: 'my-intercept-alerts' },
            { key: 'token', label: 'Access token', placeholder: 'Optional', secret: true },
        ],
        telegram: [
            { key: 'bot_token', label: 'Bot token', placeholder: '123456:ABC...', secret: true },
            { key: 'chat_id', label: 'Chat ID', placeholder: '123456789' },
        ],
        webhook: [
            { key: 'url', label: 'Address', placeholder: 'https://example.com/hook' },
            { key: 'token', label: 'Bearer token', placeholder: 'Optional', secret: true },
        ],
    };

    let watchlistsData = [];

    let alerts = [];
    let rules = [];
    let eventSource = null;
    let reconnectTimer = null;
    let lastConnectionWarningAt = 0;
    let rulesLoaded = false;
    let rulesPromise = null;
    let bootTimer = null;
    let feedLoaded = false;

    function init(options = {}) {
        const connectFeed = options.connectFeed !== false;
        const refreshRules = options.refreshRules === true;

        if (bootTimer) {
            clearTimeout(bootTimer);
            bootTimer = null;
        }

        loadRules(refreshRules);
        if (document.getElementById('watchlistsList')) {
            loadWatchlists();
            loadChannels();
            loadLimits();
            renderChannelFields();
        }

        if (connectFeed) {
            if (!feedLoaded) {
                loadFeed();
            }
            connect();
        }
    }

    function scheduleInit(delayMs = 15000) {
        if (bootTimer || eventSource) return;
        bootTimer = window.setTimeout(() => {
            bootTimer = null;
            init();
        }, delayMs);
    }

    function connect() {
        if (eventSource) {
            return;
        }

        eventSource = new EventSource('/alerts/stream');
        eventSource.onmessage = function(e) {
            try {
                const data = JSON.parse(e.data);
                if (data.type === 'keepalive') return;
                handleAlert(data);
            } catch (err) {
                console.error('[Alerts] SSE parse error', err);
            }
        };

        eventSource.onerror = function() {
            const now = Date.now();
            const offline = (typeof window.isOffline === 'function' && window.isOffline()) ||
                (typeof navigator !== 'undefined' && navigator.onLine === false);
            const shouldLog = !offline && !document.hidden && (now - lastConnectionWarningAt) > 15000;
            if (shouldLog) {
                lastConnectionWarningAt = now;
                console.warn('[Alerts] SSE connection error; retrying');
            }
            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }
            if (reconnectTimer) clearTimeout(reconnectTimer);
            reconnectTimer = setTimeout(connect, 2500);
        };
    }

    function handleAlert(alert) {
        alerts.unshift(alert);
        alerts = alerts.slice(0, 60);
        updateFeedUI();

        const severity = String(alert.severity || '').toLowerCase();
        if (typeof showNotification === 'function' && ['high', 'critical'].includes(severity)) {
            showNotification(alert.title || 'Alert', alert.message || 'Alert triggered');
        }

        if (typeof showAppToast === 'function' && ['high', 'critical'].includes(severity)) {
            showAppToast(alert.title || 'Alert', alert.message || 'Alert triggered', 'warning');
        }
    }

    function updateFeedUI() {
        const list = document.getElementById('alertsFeedList');
        const countEl = document.getElementById('alertsFeedCount');
        if (countEl) countEl.textContent = `(${alerts.length})`;
        if (!list) return;

        if (alerts.length === 0) {
            list.innerHTML = '<div class="settings-feed-empty">No alerts yet</div>';
            return;
        }

        list.innerHTML = alerts.map((alert) => {
            const title = escapeHtml(alert.title || 'Alert');
            const message = escapeHtml(alert.message || '');
            const severity = escapeHtml(alert.severity || 'medium');
            const createdAt = alert.created_at ? new Date(alert.created_at).toLocaleString() : '';
            const delivery = DELIVERY_LABELS[alert.delivery] || '';
            return `
                <div class="settings-feed-item">
                    <div class="settings-feed-title">
                        <span>${title}</span>
                        <span style="color: var(--text-dim);">${severity.toUpperCase()}</span>
                    </div>
                    <div class="settings-feed-meta">${message}</div>
                    <div class="settings-feed-meta" style="margin-top: 4px;">${createdAt}${delivery ? ` · ${escapeHtml(delivery)}` : ''}</div>
                </div>
            `;
        }).join('');
    }

    function renderRulesUI() {
        const list = document.getElementById('alertsRulesList');
        if (!list) return;

        if (!rules.length) {
            list.innerHTML = '<div class="settings-feed-empty">No rules yet</div>';
            return;
        }

        list.innerHTML = rules.map((rule) => {
            const enabled = Boolean(rule.enabled);
            const mode = rule.mode || 'all';
            const eventType = rule.event_type || 'any';
            const severity = (rule.severity || 'medium').toUpperCase();
            const match = formatMatch(rule.match);
            const statusText = enabled ? 'ENABLED' : 'DISABLED';

            return `
                <div class="settings-feed-item" style="border-left: 2px solid ${enabled ? 'var(--accent-green)' : 'var(--text-dim)'};">
                    <div class="settings-feed-title" style="display:flex; gap:8px; align-items:center; justify-content:space-between;">
                        <span>${escapeHtml(rule.name || 'Rule')}</span>
                        <span style="color: var(--text-dim); font-size: 10px;">${statusText}</span>
                    </div>
                    <div class="settings-feed-meta">Mode: ${escapeHtml(mode)} | Event: ${escapeHtml(eventType)} | Severity: ${escapeHtml(severity)}</div>
                    <div class="settings-feed-meta">Match: ${escapeHtml(match)}</div>
                    <div style="display:flex; gap:8px; margin-top: 8px;">
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px;" onclick="AlertCenter.editRule(${Number(rule.id)})">Edit</button>
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px;" onclick="AlertCenter.toggleRule(${Number(rule.id)}, ${enabled ? 'false' : 'true'})">${enabled ? 'Disable' : 'Enable'}</button>
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px; border-color: var(--accent-red); color: var(--accent-red);" onclick="AlertCenter.deleteRule(${Number(rule.id)})">Delete</button>
                    </div>
                </div>
            `;
        }).join('');
    }

    function formatMatch(match) {
        if (!match || typeof match !== 'object' || !Object.keys(match).length) {
            return 'none';
        }
        const [k, v] = Object.entries(match)[0];
        return `${k}=${v}`;
    }

    function loadFeed() {
        feedLoaded = true;
        fetch('/alerts/events?limit=30')
            .then((r) => r.json())
            .then((data) => {
                if (data.status === 'success') {
                    alerts = data.events || [];
                    updateFeedUI();
                }
            })
            .catch((err) => console.error('[Alerts] Load feed failed', err));
    }

    function loadRules(force = false) {
        if (!force && rulesLoaded) {
            renderRulesUI();
            return Promise.resolve(rules);
        }
        if (!force && rulesPromise) {
            return rulesPromise;
        }

        rulesPromise = fetch('/alerts/rules?all=1')
            .then((r) => r.json())
            .then((data) => {
                if (data.status === 'success') {
                    rules = data.rules || [];
                    rulesLoaded = true;
                    renderRulesUI();
                }
                return rules;
            })
            .catch((err) => {
                console.error('[Alerts] Load rules failed', err);
                if (typeof reportActionableError === 'function') {
                    reportActionableError('Alert Rules', err, { onRetry: loadRules });
                }
                throw err;
            })
            .finally(() => {
                rulesPromise = null;
            });

        return rulesPromise;
    }

    function saveRule() {
        const editingId = getEditingRuleId();
        const payload = buildRulePayload();

        if (!payload.name) {
            payload.name = payload.mode ? `${payload.mode} alert` : 'Alert Rule';
        }

        const url = editingId ? `/alerts/rules/${editingId}` : '/alerts/rules';
        const method = editingId ? 'PATCH' : 'POST';

        fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        })
            .then((r) => r.json())
            .then((data) => {
                if (data.status !== 'success') {
                    throw new Error(data.message || 'Failed to save rule');
                }
                clearRuleForm();
                return loadRules();
            })
            .then(() => {
                if (typeof showAppToast === 'function') {
                    showAppToast('Alerts', editingId ? 'Rule updated' : 'Rule created', 'info');
                }
            })
            .catch((err) => {
                if (typeof reportActionableError === 'function') {
                    reportActionableError('Save Alert Rule', err);
                }
            });
    }

    function buildRulePayload() {
        const nameEl = document.getElementById('alertsRuleName');
        const modeEl = document.getElementById('alertsRuleMode');
        const eventTypeEl = document.getElementById('alertsRuleEventType');
        const keyEl = document.getElementById('alertsRuleMatchKey');
        const valueEl = document.getElementById('alertsRuleMatchValue');
        const severityEl = document.getElementById('alertsRuleSeverity');

        const match = {};
        const key = keyEl ? String(keyEl.value || '').trim() : '';
        const value = valueEl ? String(valueEl.value || '').trim() : '';
        if (key && value) {
            match[key] = value;
        }

        return {
            name: nameEl ? String(nameEl.value || '').trim() : 'Alert Rule',
            mode: modeEl ? String(modeEl.value || '').trim() || null : null,
            event_type: eventTypeEl ? String(eventTypeEl.value || '').trim() || null : null,
            match,
            severity: severityEl ? String(severityEl.value || 'medium') : 'medium',
            enabled: true,
            notify: { webhook: true },
        };
    }

    function clearRuleForm() {
        setField('alertsRuleName', '');
        setField('alertsRuleMode', '');
        setField('alertsRuleEventType', '');
        setField('alertsRuleMatchKey', '');
        setField('alertsRuleMatchValue', '');
        setField('alertsRuleSeverity', 'medium');
        setField('alertsRuleEditingId', '');
    }

    function editRule(ruleId) {
        const rule = rules.find((r) => Number(r.id) === Number(ruleId));
        if (!rule) return;

        const matchEntries = Object.entries(rule.match || {});
        const firstMatch = matchEntries.length ? matchEntries[0] : ['', ''];

        setField('alertsRuleName', rule.name || '');
        setField('alertsRuleMode', rule.mode || '');
        setField('alertsRuleEventType', rule.event_type || '');
        setField('alertsRuleMatchKey', firstMatch[0] || '');
        setField('alertsRuleMatchValue', firstMatch[1] == null ? '' : String(firstMatch[1]));
        setField('alertsRuleSeverity', rule.severity || 'medium');
        setField('alertsRuleEditingId', String(rule.id));
    }

    function toggleRule(ruleId, enabled) {
        fetch(`/alerts/rules/${ruleId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: Boolean(enabled) }),
        })
            .then((r) => r.json())
            .then((data) => {
                if (data.status !== 'success') {
                    throw new Error(data.message || 'Failed to update rule');
                }
                return loadRules(true);
            })
            .catch((err) => {
                if (typeof reportActionableError === 'function') {
                    reportActionableError('Toggle Alert Rule', err);
                }
            });
    }

    async function deleteRule(ruleId) {
        const confirmed = await AppFeedback.confirmAction({
            title: 'Delete Alert Rule',
            message: 'Delete this alert rule?',
            confirmLabel: 'Delete',
            confirmClass: 'btn-danger'
        });
        if (!confirmed) return;

        fetch(`/alerts/rules/${ruleId}`, { method: 'DELETE' })
            .then((r) => r.json())
            .then((data) => {
                if (data.status !== 'success') {
                    throw new Error(data.message || 'Failed to delete rule');
                }
                if (Number(getEditingRuleId()) === Number(ruleId)) {
                    clearRuleForm();
                }
                return loadRules(true);
            })
            .catch((err) => {
                if (typeof reportActionableError === 'function') {
                    reportActionableError('Delete Alert Rule', err);
                }
            });
    }

    function getEditingRuleId() {
        const el = document.getElementById('alertsRuleEditingId');
        if (!el || !el.value) return null;
        const parsed = Number(el.value);
        return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
    }

    function setField(id, value) {
        const el = document.getElementById(id);
        if (!el) return;
        el.value = value;
    }

    function enableTrackerAlerts() {
        ensureTrackerRule(true);
    }

    function disableTrackerAlerts() {
        ensureTrackerRule(false);
    }

    function ensureTrackerRule(enabled) {
        loadRules().then(() => {
            const existing = rules.find((r) => r.name === TRACKER_RULE_NAME);
            if (existing) {
                return fetch(`/alerts/rules/${existing.id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled }),
                }).then(() => loadRules(true));
            }

            if (enabled) {
                return fetch('/alerts/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: TRACKER_RULE_NAME,
                        mode: 'bluetooth',
                        event_type: 'device_update',
                        match: { is_tracker: true },
                        severity: 'high',
                        enabled: true,
                        notify: { webhook: true },
                    }),
                }).then(() => loadRules(true));
            }
            return null;
        });
    }

    function addBluetoothWatchlist(address, name) {
        if (!address) return;
        loadRules().then(() => {
            const upper = String(address).toUpperCase();
            const existing = rules.find((r) => r.mode === 'bluetooth' && r.match && String(r.match.address || '').toUpperCase() === upper);
            if (existing) return;

            return fetch('/alerts/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: name ? `Watchlist ${name}` : `Watchlist ${upper}`,
                    mode: 'bluetooth',
                    event_type: 'device_update',
                    match: { address: upper },
                    severity: 'medium',
                    enabled: true,
                    notify: { webhook: true },
                }),
            }).then(() => loadRules(true));
        });
    }

    function removeBluetoothWatchlist(address) {
        if (!address) return;
        loadRules().then(() => {
            const upper = String(address).toUpperCase();
            const existing = rules.find((r) => r.mode === 'bluetooth' && r.match && String(r.match.address || '').toUpperCase() === upper);
            if (!existing) return;

            return fetch(`/alerts/rules/${existing.id}`, { method: 'DELETE' })
                .then(() => loadRules(true));
        });
    }

    function isWatchlisted(address) {
        if (!address) return false;
        if (!rulesLoaded && !rulesPromise) {
            loadRules();
        }
        const upper = String(address).toUpperCase();
        return rules.some((r) => r.mode === 'bluetooth' && r.match && String(r.match.address || '').toUpperCase() === upper && r.enabled);
    }

    // ------------------------------------------------------------------
    // Watchlists, push channels and limits
    // ------------------------------------------------------------------

    async function apiJson(url, options) {
        const resp = await fetch(url, options);
        const data = await resp.json();
        if (data.status !== 'success') {
            throw new Error(data.message || `Request failed (${resp.status})`);
        }
        return data;
    }

    function jsonBody(method, body) {
        return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    }

    function reportError(title, err) {
        if (typeof reportActionableError === 'function') {
            reportActionableError(title, err);
        } else if (typeof showAppToast === 'function') {
            showAppToast(title, err.message, 'error');
        }
    }

    function toast(message) {
        if (typeof showAppToast === 'function') showAppToast('Alerts', message, 'info');
    }

    function updateWatchlistKindHint() {
        const kind = (document.getElementById('watchlistKind') || {}).value || 'aircraft';
        const hint = document.getElementById('watchlistKindHint');
        if (hint) hint.textContent = WATCHLIST_HINTS[kind] || '';
        const tolRow = document.getElementById('watchlistToleranceRow');
        // .settings-row sets display, which would override the hidden attribute
        if (tolRow) tolRow.style.display = kind === 'frequency' ? '' : 'none';
    }

    function loadWatchlists() {
        return apiJson('/alerts/watchlists')
            .then((data) => {
                watchlistsData = data.watchlists || [];
                renderWatchlists();
            })
            .catch((err) => reportError('Watchlists', err));
    }

    function renderWatchlists() {
        const list = document.getElementById('watchlistsList');
        if (!list) return;
        if (!watchlistsData.length) {
            list.innerHTML = '<div class="settings-feed-empty">No watchlists yet</div>';
            return;
        }
        list.innerHTML = watchlistsData.map((wl) => {
            const enabled = Boolean(wl.enabled);
            const entries = wl.entries || [];
            const preview = entries.slice(0, 6).join(', ') + (entries.length > 6 ? ` +${entries.length - 6} more` : '');
            return `
                <div class="settings-feed-item" style="border-left: 2px solid ${enabled ? 'var(--accent-green)' : 'var(--text-dim)'};">
                    <div class="settings-feed-title" style="display:flex; gap:8px; align-items:center; justify-content:space-between;">
                        <span>${escapeHtml(wl.name)}</span>
                        <span style="color: var(--text-dim); font-size: 10px;">${escapeHtml(wl.kind.toUpperCase())} · ${escapeHtml((wl.severity || 'medium').toUpperCase())}${enabled ? '' : ' · DISABLED'}</span>
                    </div>
                    <div class="settings-feed-meta">${escapeHtml(preview || 'no entries')}</div>
                    <div style="display:flex; gap:8px; margin-top: 8px;">
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px;" onclick="AlertCenter.editWatchlist(${Number(wl.id)})">Edit</button>
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px;" onclick="AlertCenter.toggleWatchlist(${Number(wl.id)}, ${enabled ? 'false' : 'true'})">${enabled ? 'Disable' : 'Enable'}</button>
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px; border-color: var(--accent-red); color: var(--accent-red);" onclick="AlertCenter.deleteWatchlist(${Number(wl.id)})">Delete</button>
                    </div>
                </div>`;
        }).join('');
    }

    function saveWatchlist() {
        const editingId = Number((document.getElementById('watchlistEditingId') || {}).value || 0);
        const kind = document.getElementById('watchlistKind').value;
        const body = {
            name: document.getElementById('watchlistName').value.trim() || kind,
            kind,
            entries: document.getElementById('watchlistEntries').value,
            severity: document.getElementById('watchlistSeverity').value,
        };
        if (kind === 'frequency') {
            body.tolerance_khz = Number(document.getElementById('watchlistTolerance').value || 0);
        }
        const request = editingId
            ? apiJson(`/alerts/watchlists/${editingId}`, jsonBody('PATCH', body))
            : apiJson('/alerts/watchlists', jsonBody('POST', body));
        request
            .then(() => {
                clearWatchlistForm();
                toast(editingId ? 'Watchlist updated' : 'Watchlist created');
                return loadWatchlists();
            })
            .catch((err) => reportError('Save Watchlist', err));
    }

    function clearWatchlistForm() {
        setField('watchlistName', '');
        setField('watchlistKind', 'aircraft');
        setField('watchlistEntries', '');
        setField('watchlistSeverity', 'medium');
        setField('watchlistTolerance', '5');
        setField('watchlistEditingId', '');
        updateWatchlistKindHint();
    }

    function editWatchlist(id) {
        const wl = watchlistsData.find((w) => Number(w.id) === Number(id));
        if (!wl) return;
        setField('watchlistName', wl.name);
        setField('watchlistKind', wl.kind);
        setField('watchlistEntries', (wl.entries || []).join('\n'));
        setField('watchlistSeverity', wl.severity || 'medium');
        setField('watchlistTolerance', String(wl.tolerance_khz ?? 5));
        setField('watchlistEditingId', String(wl.id));
        updateWatchlistKindHint();
    }

    function toggleWatchlist(id, enabled) {
        apiJson(`/alerts/watchlists/${id}`, jsonBody('PATCH', { enabled: Boolean(enabled) }))
            .then(loadWatchlists)
            .catch((err) => reportError('Toggle Watchlist', err));
    }

    async function deleteWatchlist(id) {
        const confirmed = await AppFeedback.confirmAction({
            title: 'Delete Watchlist',
            message: 'Delete this watchlist?',
            confirmLabel: 'Delete',
            confirmClass: 'btn-danger'
        });
        if (!confirmed) return;
        apiJson(`/alerts/watchlists/${id}`, { method: 'DELETE' })
            .then(() => {
                if (Number((document.getElementById('watchlistEditingId') || {}).value) === Number(id)) {
                    clearWatchlistForm();
                }
                return loadWatchlists();
            })
            .catch((err) => reportError('Delete Watchlist', err));
    }

    function renderChannelFields() {
        const container = document.getElementById('channelFields');
        const kindEl = document.getElementById('channelKind');
        if (!container || !kindEl) return;
        container.innerHTML = (CHANNEL_FIELDS[kindEl.value] || []).map((f) => `
            <div class="settings-row" style="border-bottom: none;">
                <div class="settings-label">
                    <span class="settings-label-text">${escapeHtml(f.label)}</span>
                </div>
                <input type="${f.secret ? 'password' : 'text'}" class="settings-input" data-channel-field="${escapeHtml(f.key)}"
                    placeholder="${escapeHtml(f.placeholder)}" autocomplete="off" style="width: 220px;">
            </div>`).join('');
    }

    function loadChannels() {
        return apiJson('/alerts/channels')
            .then((data) => renderChannels(data.channels || []))
            .catch((err) => reportError('Push Channels', err));
    }

    function renderChannels(channels) {
        const list = document.getElementById('channelsList');
        if (!list) return;
        if (!channels.length) {
            list.innerHTML = '<div class="settings-feed-empty">No channels yet</div>';
            return;
        }
        list.innerHTML = channels.map((ch) => {
            const enabled = Boolean(ch.enabled);
            const cfg = ch.config || {};
            const where = cfg.topic ? `${cfg.server || ''} / ${cfg.topic}` : (cfg.url || (cfg.chat_id ? `chat ${cfg.chat_id}` : ''));
            return `
                <div class="settings-feed-item" style="border-left: 2px solid ${enabled ? 'var(--accent-green)' : 'var(--text-dim)'};">
                    <div class="settings-feed-title" style="display:flex; gap:8px; align-items:center; justify-content:space-between;">
                        <span>${escapeHtml(ch.name)}</span>
                        <span style="color: var(--text-dim); font-size: 10px;">${escapeHtml(ch.kind.toUpperCase())}${enabled ? '' : ' · DISABLED'}</span>
                    </div>
                    <div class="settings-feed-meta">${escapeHtml(where)}</div>
                    <div style="display:flex; gap:8px; margin-top: 8px;">
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px;" onclick="AlertCenter.testChannels(${Number(ch.id)})">Test</button>
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px;" onclick="AlertCenter.toggleChannel(${Number(ch.id)}, ${enabled ? 'false' : 'true'})">${enabled ? 'Disable' : 'Enable'}</button>
                        <button class="preset-btn" style="font-size: 10px; padding: 3px 8px; border-color: var(--accent-red); color: var(--accent-red);" onclick="AlertCenter.deleteChannel(${Number(ch.id)})">Delete</button>
                    </div>
                </div>`;
        }).join('');
    }

    function saveChannel() {
        const kind = document.getElementById('channelKind').value;
        const config = {};
        document.querySelectorAll('#channelFields [data-channel-field]').forEach((input) => {
            config[input.dataset.channelField] = input.value.trim();
        });
        const name = document.getElementById('channelName').value.trim() || kind;
        apiJson('/alerts/channels', jsonBody('POST', { kind, name, config, enabled: true }))
            .then(() => {
                setField('channelName', '');
                renderChannelFields();
                toast('Channel added');
                return loadChannels();
            })
            .catch((err) => reportError('Add Channel', err));
    }

    function toggleChannel(id, enabled) {
        apiJson(`/alerts/channels/${id}`, jsonBody('PATCH', { enabled: Boolean(enabled) }))
            .then(loadChannels)
            .catch((err) => reportError('Toggle Channel', err));
    }

    async function deleteChannel(id) {
        const confirmed = await AppFeedback.confirmAction({
            title: 'Delete Channel',
            message: 'Delete this push channel and its stored token?',
            confirmLabel: 'Delete',
            confirmClass: 'btn-danger'
        });
        if (!confirmed) return;
        apiJson(`/alerts/channels/${id}`, { method: 'DELETE' })
            .then(loadChannels)
            .catch((err) => reportError('Delete Channel', err));
    }

    function testChannels(id) {
        const url = id ? `/alerts/channels/${id}/test` : '/alerts/test';
        apiJson(url, { method: 'POST' })
            .then((data) => {
                const results = data.results || [];
                const failed = results.filter((r) => !r.ok);
                const summary = results.map((r) => `${r.channel}: ${r.ok ? 'sent' : `failed (${r.error})`}`).join(', ');
                if (typeof showAppToast === 'function') {
                    showAppToast('Test Alert', summary, failed.length ? 'warning' : 'info');
                }
            })
            .catch((err) => reportError('Test Alert', err));
    }

    function loadLimits() {
        return apiJson('/alerts/limits')
            .then((data) => {
                const l = data.limits || {};
                setField('limitMaxPerHour', String(l.max_per_hour ?? ''));
                setField('limitCooldown', String(l.cooldown_minutes ?? ''));
                setField('limitQuietStart', l.quiet_start || '');
                setField('limitQuietEnd', l.quiet_end || '');
            })
            .catch((err) => reportError('Alert Limits', err));
    }

    function saveLimits() {
        const body = {
            max_per_hour: Number(document.getElementById('limitMaxPerHour').value || 0),
            cooldown_minutes: Number(document.getElementById('limitCooldown').value || 0),
            quiet_start: document.getElementById('limitQuietStart').value || '',
            quiet_end: document.getElementById('limitQuietEnd').value || '',
        };
        apiJson('/alerts/limits', jsonBody('PATCH', body))
            .then(() => toast('Limits saved'))
            .catch((err) => reportError('Save Limits', err));
    }

    function destroy() {
        if (bootTimer) {
            clearTimeout(bootTimer);
            bootTimer = null;
        }
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    return {
        init,
        scheduleInit,
        loadFeed,
        loadRules,
        saveRule,
        clearRuleForm,
        editRule,
        toggleRule,
        deleteRule,
        enableTrackerAlerts,
        disableTrackerAlerts,
        addBluetoothWatchlist,
        removeBluetoothWatchlist,
        isWatchlisted,
        updateWatchlistKindHint,
        saveWatchlist,
        clearWatchlistForm,
        editWatchlist,
        toggleWatchlist,
        deleteWatchlist,
        renderChannelFields,
        saveChannel,
        toggleChannel,
        deleteChannel,
        testChannels,
        saveLimits,
        destroy,
    };
})();

document.addEventListener('DOMContentLoaded', () => {
    if (typeof AlertCenter !== 'undefined') {
        AlertCenter.scheduleInit();
    }
});
