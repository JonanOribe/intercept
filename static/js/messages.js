// Messages page: search, page through and export the decoded-message database.
(function () {
    'use strict';

    const MODE_LABELS = {
        pager: 'Pager', sensor: '433 Sensors', rtlamr: 'Meters', adsb: 'ADS-B', acars: 'ACARS', vdl2: 'VDL2',
        ais: 'AIS', dsc: 'DSC', aprs: 'APRS', radiosonde: 'Radiosonde', drone: 'Drone', wifi: 'WiFi',
        bluetooth: 'Bluetooth', meshtastic: 'Meshtastic', subghz: 'Sub-GHz', ook: 'OOK', tscm: 'TSCM',
        receiver_scanner: 'Scanner', sstv: 'SSTV', sstv_general: 'SSTV (HF)', morse: 'Morse',
    };

    const el = (id) => document.getElementById(id);
    const resultBody = el('resultBody');
    const moreBtn = el('moreBtn');
    let nextBeforeId = null;
    let shown = 0;
    let selectedRow = null;

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    function toast(title, message, type) {
        if (typeof showAppToast === 'function') showAppToast(title, message, type || 'info');
    }

    function fmtTime(ts) {
        return ts ? new Date(ts * 1000).toLocaleString() : '--';
    }

    function fmtFreq(hz) {
        if (!hz) return '';
        return hz >= 1e6 ? `${(hz / 1e6).toFixed(4)} MHz` : `${(hz / 1e3).toFixed(1)} kHz`;
    }

    function fmtBytes(n) {
        if (!n) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
        return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
    }

    function filterParams() {
        const p = new URLSearchParams();
        const q = el('qInput').value.trim();
        const mode = el('modeSelect').value;
        const ident = el('identInput').value.trim();
        const windowMin = el('windowSelect').value;
        if (q) p.set('q', q);
        if (mode) p.set('mode', mode);
        if (ident) p.set('ident', ident);
        if (windowMin) p.set('since', String(Date.now() / 1000 - Number(windowMin) * 60));
        if (el('posCheck').checked) p.set('has_position', '1');
        return p;
    }

    async function getJson(url, options) {
        const resp = await fetch(url, options);
        const data = await resp.json();
        if (data.status !== 'success') throw new Error(data.message || `Request failed (${resp.status})`);
        return data;
    }

    async function search(append) {
        const p = filterParams();
        p.set('limit', '200');
        if (append && nextBeforeId) p.set('before_id', String(nextBeforeId));
        try {
            const data = await getJson(`/messages/search?${p}`);
            if (!append) {
                resultBody.innerHTML = '';
                shown = 0;
            }
            renderRows(data.messages || []);
            nextBeforeId = data.next_before_id;
            moreBtn.hidden = !nextBeforeId;
            el('resultMeta').textContent = nextBeforeId ? `${shown}+` : String(shown);
            if (!shown) {
                resultBody.innerHTML = '<tr class="empty-row"><td colspan="5">Nothing matches. Messages appear here as the decoders hear them.</td></tr>';
            }
        } catch (err) {
            toast('Messages', err.message, 'error');
        }
    }

    function renderRows(rows) {
        const html = rows.map((m) => `
            <tr class="aircraft-row" data-id="${Number(m.id)}">
                <td class="mono msg-nowrap">${escapeHtml(fmtTime(m.ts))}</td>
                <td><span class="civ-badge">${escapeHtml(MODE_LABELS[m.mode] || m.mode)}</span></td>
                <td class="mono">${escapeHtml(m.ident || '')}</td>
                <td class="mono msg-nowrap">${escapeHtml(fmtFreq(m.freq_hz))}</td>
                <td class="msg-summary">${escapeHtml(m.summary || '')}${m.lat != null ? ' <span class="msg-pos" title="Has position">⌖</span>' : ''}</td>
            </tr>`).join('');
        resultBody.insertAdjacentHTML('beforeend', html);
        shown += rows.length;
    }

    async function showDetail(id, row) {
        if (selectedRow) selectedRow.classList.remove('msg-selected');
        selectedRow = row;
        row.classList.add('msg-selected');
        try {
            const { message: m } = await getJson(`/messages/${id}`);
            el('detailMeta').textContent = `#${m.id}`;
            const facts = [
                ['Time', fmtTime(m.ts)],
                ['Mode', MODE_LABELS[m.mode] || m.mode],
                ['Type', m.event_type],
                ['Identity', m.ident],
                ['Also known as', (m.aliases || []).join(', ')],
                ['Frequency', fmtFreq(m.freq_hz)],
                ['Position', m.lat != null ? `${m.lat.toFixed(5)}, ${m.lon.toFixed(5)}` : ''],
            ].filter(([, v]) => v);
            el('detailBody').innerHTML = `
                <div class="detail-card">
                    <div class="detail-title">${escapeHtml(m.summary || m.ident || m.mode)}</div>
                    ${m.text ? `<div class="msg-text">${escapeHtml(m.text)}</div>` : ''}
                    <dl class="msg-facts">${facts.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`).join('')}</dl>
                    ${m.ident ? `<button class="primary-btn msg-more" type="button" id="sameIdentBtn">All from ${escapeHtml(m.ident)}</button>` : ''}
                </div>
                <div class="detail-card">
                    <div class="detail-title">Decoded fields</div>
                    <pre class="msg-json">${escapeHtml(JSON.stringify(m.payload, null, 2))}</pre>
                </div>`;
            const sameBtn = el('sameIdentBtn');
            if (sameBtn) {
                sameBtn.addEventListener('click', () => {
                    el('identInput').value = m.ident;
                    el('modeSelect').value = m.mode;
                    el('qInput').value = '';
                    search(false);
                });
            }
        } catch (err) {
            toast('Messages', err.message, 'error');
        }
    }

    async function loadStats() {
        try {
            const s = await getJson('/messages/stats');
            el('sumTotal').textContent = Number(s.total).toLocaleString();
            el('sumSize').textContent = fmtBytes(s.used_bytes);
            el('sumOldest').textContent = s.oldest_ts ? new Date(s.oldest_ts * 1000).toLocaleDateString() : '--';
            const busiest = Object.entries(s.by_mode || {}).sort((a, b) => b[1] - a[1])[0];
            el('sumBusiest').textContent = busiest ? (MODE_LABELS[busiest[0]] || busiest[0]) : '--';

            const select = el('modeSelect');
            const current = select.value;
            const modes = Object.keys(s.by_mode || {}).sort();
            select.innerHTML = '<option value="">All modes</option>' + modes
                .map((m) => `<option value="${escapeHtml(m)}">${escapeHtml(MODE_LABELS[m] || m)} (${s.by_mode[m]})</option>`)
                .join('');
            select.value = modes.includes(current) ? current : '';

            const st = s.settings || {};
            el('enabledCheck').checked = Boolean(st.enabled);
            el('maxRowsInput').value = st.max_rows;
            el('maxMbInput').value = st.max_mb;
            el('maxDaysInput').value = st.max_days;
            if (!s.full_text_search) {
                el('qInput').placeholder = 'substring search (this SQLite has no full-text index)';
            }
        } catch (err) {
            toast('Messages', err.message, 'error');
        }
    }

    async function saveStorage(e) {
        e.preventDefault();
        try {
            await getJson('/messages/settings', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    enabled: el('enabledCheck').checked,
                    max_rows: Number(el('maxRowsInput').value || 0),
                    max_mb: Number(el('maxMbInput').value || 0),
                    max_days: Number(el('maxDaysInput').value || 0),
                }),
            });
            toast('Messages', 'Storage settings saved');
            loadStats();
        } catch (err) {
            toast('Messages', err.message, 'error');
        }
    }

    async function clearAll() {
        const confirmed = typeof AppFeedback !== 'undefined'
            ? await AppFeedback.confirmAction({
                title: 'Clear Messages',
                message: 'Delete every stored message? This cannot be undone.',
                confirmLabel: 'Delete All',
                confirmClass: 'btn-danger',
            })
            : false;
        if (!confirmed) return;
        try {
            const data = await getJson('/messages', { method: 'DELETE' });
            toast('Messages', `${Number(data.deleted).toLocaleString()} messages deleted`);
            loadStats();
            search(false);
        } catch (err) {
            toast('Messages', err.message, 'error');
        }
    }

    function exportMatches() {
        const p = filterParams();
        p.set('format', el('exportFormat').value);
        window.location.href = `/messages/export?${p}`;
    }

    el('filterForm').addEventListener('submit', (e) => { e.preventDefault(); search(false); });
    el('storageForm').addEventListener('submit', saveStorage);
    el('clearBtn').addEventListener('click', clearAll);
    el('exportBtn').addEventListener('click', exportMatches);
    moreBtn.addEventListener('click', () => search(true));
    resultBody.addEventListener('click', (e) => {
        const row = e.target.closest('tr[data-id]');
        if (row) showDetail(row.dataset.id, row);
    });

    const params = new URLSearchParams(window.location.search);
    if (params.get('q')) el('qInput').value = params.get('q');
    if (params.get('ident')) el('identInput').value = params.get('ident');

    loadStats().then(() => {
        if (params.get('mode')) el('modeSelect').value = params.get('mode');
        search(false);
    });
})();
