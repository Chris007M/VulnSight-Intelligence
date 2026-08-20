/**
 * VulnSight Dashboard — Advanced Client Script
 *
 * Features:
 *   - Auth flow (sendCode / verifyCode)
 *   - Multi-file upload queue with per-file progress
 *   - TableManager: search, multi-column sort, severity filter, pagination
 *   - Compliance Scorecard (PCI-DSS, NIST, ISO 27001, CIS Controls)
 *   - EPSS Exploit Prediction & CISA KEV Threat Intelligence Badges
 *   - Automated Remediation Script Generator (Bash, Ansible, PowerShell)
 *   - Scan History panel with click-to-reload
 *   - Export: CSV, JSON, PDF (browser print)
 *   - Toast notification system
 */

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────
let currentReportData   = null;
let scanHistory         = [];        // Array of report objects from server
let allTableRows        = [];        // All flattened rows for the table
let activeHistoryIdx    = -1;        // Which history item is currently shown
let currentModalHost    = '';
let currentModalRisks   = [];
let currentModalFormat  = 'bash';
let currentScriptText   = '';

// ─────────────────────────────────────────────────────────────────────────────
// ── Toast Notification System ─────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
const TOAST_ICONS = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };

function showToast(title, message, type = 'info', duration = 4500) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${TOAST_ICONS[type] || 'ℹ️'}</span>
        <div class="toast-body">
            <div class="toast-title">${title}</div>
            ${message ? `<div class="toast-msg">${message}</div>` : ''}
        </div>
        <button class="toast-close" onclick="this.closest('.toast').remove()">✕</button>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'toastOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Authentication ────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
async function sendCode() {
    const email = document.getElementById('email').value.trim();
    if (!email) { showToast('Input Required', 'Please enter a valid email address.', 'warning'); return; }

    const btn = document.getElementById('btn-send-code');
    btn.innerText = 'Sending…'; btn.disabled = true;

    try {
        const res  = await fetch('/auth/send-code', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();

        if (res.ok) {
            document.getElementById('verify-section').style.display = 'block';
            const notice = document.getElementById('dev-code-notice');
            if (data.devMode && data.devCode) {
                notice.style.display = 'block';
                notice.innerHTML = `<strong>Local Dev Mode:</strong> Your code is <code style="font-size:14px; background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:4px;">${data.devCode}</code>`;
            } else {
                notice.style.display = 'none';
            }
            showToast('Code Sent', `Verification code sent to ${email}`, 'success');
        } else {
            showToast('Failed to Send', data.error || 'Could not send verification code.', 'error');
        }
    } catch (err) {
        showToast('Network Error', err.message, 'error');
    } finally {
        btn.innerText = 'Send Verification Code'; btn.disabled = false;
    }
}

async function verifyCode() {
    const email = document.getElementById('email').value.trim();
    const code  = document.getElementById('authCode').value.trim();
    if (!code) { showToast('Input Required', 'Please enter the 6-digit verification code.', 'warning'); return; }

    try {
        const res  = await fetch('/auth/verify-code', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, code })
        });
        const data = await res.json();

        if (res.ok) {
            document.getElementById('auth-container').style.display   = 'none';
            document.getElementById('dashboard').style.display        = 'flex';
            document.getElementById('user-info').style.display        = 'block';
            document.getElementById('current-user').innerText         = email;
            loadDashboard();
            showToast('Access Granted', `Welcome, ${email}`, 'success');
        } else {
            showToast('Auth Failed', data.error || 'Invalid or expired verification code.', 'error');
        }
    } catch (err) {
        showToast('Authentication Error', err.message, 'error');
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Dashboard Bootstrap ───────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
async function loadDashboard() {
    setupDropzone();

    try {
        const res = await fetch('/api/reports');
        if (res.ok) {
            const data = await res.json();
            if (data.reports && data.reports.length > 0) {
                scanHistory = data.reports;
                renderHistoryPanel();
                const latest = data.reports[data.reports.length - 1];
                updateDashboard(latest, data.reports.length - 1);
            } else {
                renderDefaultCharts();
            }
        } else {
            renderDefaultCharts();
        }
    } catch (err) {
        console.warn('Could not load historical reports:', err);
        renderDefaultCharts();
    }
}

function renderDefaultCharts() {
    const pieCtx  = document.getElementById('riskChart').getContext('2d');
    renderRiskDistributionChart(pieCtx, [0, 0, 0, 0]);
    const trendCtx = document.getElementById('trendChart').getContext('2d');
    renderThreatTrendChart(trendCtx, ['Scan 1', 'Scan 2', 'Scan 3'], [0, 0, 0]);
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Dropzone + Multi-File Upload Queue ───────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
function setupDropzone() {
    const dropzone = document.getElementById('dropzone');
    if (!dropzone) return;

    ['dragenter', 'dragover'].forEach(ev =>
        dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('dragover'); }, false)
    );
    ['dragleave', 'drop'].forEach(ev =>
        dropzone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('dragover'); }, false)
    );
    dropzone.addEventListener('drop', e => {
        const files = e.dataTransfer.files;
        if (files && files.length > 0) processFileQueue([...files]);
    });
}

function handleFileSelect(event) {
    const files = event.target.files;
    if (files && files.length > 0) processFileQueue([...files]);
    event.target.value = '';
}

const FORMAT_ICONS = {
    xml: '📄', txt: '📝', gnmap: '📋', html: '🌐', htm: '🌐',
    xlsx: '📊', xls: '📊', csv: '🗂️', json: '📦'
};

function getFormatIcon(filename) {
    const ext = (filename.split('.').pop() || '').toLowerCase();
    return FORMAT_ICONS[ext] || '📁';
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

async function processFileQueue(files) {
    const queueEl = document.getElementById('upload-queue');

    for (const file of files) {
        const ext       = (file.name.split('.').pop() || '').toLowerCase();
        const icon      = getFormatIcon(file.name);
        const itemId    = 'qi-' + Date.now() + '-' + Math.random().toString(36).slice(2);

        const item = document.createElement('div');
        item.className = 'queue-item';
        item.id = itemId;
        item.innerHTML = `
            <span class="queue-item-icon">${icon}</span>
            <div class="queue-item-name" title="${file.name}">${file.name}</div>
            <span class="format-badge-small">${ext.toUpperCase()}</span>
            <span class="queue-item-meta">${formatFileSize(file.size)}</span>
            <div class="queue-item-progress"><div class="queue-item-progress-bar" style="width:0%" id="${itemId}-bar"></div></div>
            <span class="queue-item-status active" id="${itemId}-status">Uploading…</span>
        `;
        queueEl.appendChild(item);

        const bar = document.getElementById(`${itemId}-bar`);
        let fakeProgress = 0;
        const fakeInterval = setInterval(() => {
            fakeProgress = Math.min(fakeProgress + 8, 60);
            if (bar) bar.style.width = fakeProgress + '%';
        }, 80);

        try {
            const formData = new FormData();
            formData.append('scanFile', file);

            const res  = await fetch('/upload', { method: 'POST', body: formData });
            const data = await res.json();

            clearInterval(fakeInterval);
            if (bar) bar.style.width = '100%';

            const statusEl = document.getElementById(`${itemId}-status`);

            if (res.ok && data.success) {
                if (statusEl) { statusEl.className = 'queue-item-status done'; statusEl.textContent = `✓ Done`; }

                scanHistory.push(data.report);
                updateDashboard(data.report, scanHistory.length - 1);
                renderHistoryPanel();

                showToast(
                    'Scan Processed',
                    `${file.name} — ${data.hostsFound} host(s) analysed via ${data.formatDetected}`,
                    'success'
                );
            } else {
                if (statusEl) { statusEl.className = 'queue-item-status error'; statusEl.textContent = '✗ Failed'; }
                showToast('Upload Failed', data.error || 'Unknown error', 'error');
            }
        } catch (err) {
            clearInterval(fakeInterval);
            const statusEl = document.getElementById(`${itemId}-status`);
            if (statusEl) { statusEl.className = 'queue-item-status error'; statusEl.textContent = '✗ Error'; }
            showToast('Server Error', err.message, 'error');
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Dashboard Metrics, Compliance & Charts Update ─────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
function updateDashboard(report, historyIndex) {
    if (!report || !report.summary) return;
    currentReportData = report;
    activeHistoryIdx  = historyIndex;

    document.getElementById('threats').innerText        = report.summary.totalHosts   || 0;
    document.getElementById('critical-count').innerText = report.summary.critical   || 0;
    document.getElementById('high-count').innerText     = report.summary.high         || 0;
    document.getElementById('defended').innerText       = (report.summary.medium || 0) + (report.summary.low || 0);
    document.getElementById('system-cvss').innerText    = report.summary.overallCvssScore !== undefined
        ? report.summary.overallCvssScore.toFixed(1) : '0.0';

    // Compliance Scorecard Update
    updateComplianceScorecard(report.compliance);

    // Charts
    const pieCtx = document.getElementById('riskChart').getContext('2d');
    renderRiskDistributionChart(pieCtx, [
        report.summary.critical || 0, report.summary.high || 0,
        report.summary.medium   || 0, report.summary.low  || 0
    ]);

    const trendCtx   = document.getElementById('trendChart').getContext('2d');
    const trendLabels = scanHistory.map((_, i) => `Scan ${i + 1}`);
    const trendVals   = scanHistory.map(r => r.summary ? r.summary.totalRisks : 0);
    renderThreatTrendChart(
        trendCtx,
        trendLabels.length ? trendLabels : ['Current'],
        trendVals.length   ? trendVals   : [report.summary.totalRisks || 0]
    );

    // Build flat row list for the table
    buildTableRows(report);

    // Highlight active history item
    document.querySelectorAll('.history-item').forEach((el, i) => {
        el.classList.toggle('active', i === historyIndex);
    });
}

function updateComplianceScorecard(compliance) {
    if (!compliance) return;

    const frameworks = [
        { key: 'pciDss',      scoreId: 'score-pci',  barId: 'bar-pci',  statusId: 'status-pci' },
        { key: 'nist',        scoreId: 'score-nist', barId: 'bar-nist', statusId: 'status-nist' },
        { key: 'iso27001',    scoreId: 'score-iso',  barId: 'bar-iso',  statusId: 'status-iso' },
        { key: 'cisControls', scoreId: 'score-cis',  barId: 'bar-cis',  statusId: 'status-cis' }
    ];

    frameworks.forEach(f => {
        const item = compliance[f.key];
        if (!item) return;

        const scoreEl  = document.getElementById(f.scoreId);
        const barEl    = document.getElementById(f.barId);
        const statusEl = document.getElementById(f.statusId);

        const score = item.score !== undefined ? item.score : 100;

        if (scoreEl) scoreEl.textContent = `${score}%`;
        if (barEl)   barEl.style.width   = `${score}%`;

        if (statusEl) {
            if (item.passed) {
                statusEl.textContent = '✓ Compliant';
                statusEl.className   = 'compliance-status';
            } else {
                statusEl.textContent = `⚠️ Action Needed (${item.rulesTriggered.length} findings)`;
                statusEl.className   = 'compliance-status failed';
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Scan History Panel ────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
function renderHistoryPanel() {
    const panel   = document.getElementById('scan-history-panel');
    const countEl = document.getElementById('history-count');
    panel.innerHTML = '';

    if (!scanHistory || scanHistory.length === 0) {
        panel.innerHTML = '<div class="history-empty">No scan history yet. Upload a scan file to begin.</div>';
        countEl.textContent = 'No scans loaded';
        return;
    }

    countEl.textContent = `${scanHistory.length} scan${scanHistory.length !== 1 ? 's' : ''} in history`;

    scanHistory.forEach((report, idx) => {
        const s     = report.summary || {};
        const ts    = report.timestamp ? new Date(report.timestamp).toLocaleString() : 'Unknown time';
        const fname = report.filename || report.reportId || `Report ${idx + 1}`;

        const item = document.createElement('div');
        item.className = 'history-item' + (idx === activeHistoryIdx ? ' active' : '');
        item.onclick = () => updateDashboard(report, idx);
        item.innerHTML = `
            <span class="history-icon">📋</span>
            <div class="history-info">
                <div class="history-filename" title="${fname}">${fname}</div>
                <div class="history-meta">${ts} · ${s.totalHosts || 0} hosts · ${s.totalRisks || 0} risks</div>
            </div>
            <div class="history-risk-badges">
                ${s.critical ? `<span class="risk-mini critical">C:${s.critical}</span>` : ''}
                ${s.high     ? `<span class="risk-mini high">H:${s.high}</span>`         : ''}
                ${s.medium   ? `<span class="risk-mini medium">M:${s.medium}</span>`     : ''}
            </div>
        `;
        panel.appendChild(item);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Table Manager ─────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
function buildTableRows(report) {
    allTableRows = [];
    if (!report.details) { tableManager.setRows([]); return; }

    report.details.forEach(host => {
        if (!host.risks || host.risks.length === 0) {
            allTableRows.push({
                host: host.ip, hostname: host.hostname || '',
                severity: 'Low', severityOrder: 4,
                cvss: 0,
                ports: 'No open vulnerable ports detected',
                cves: [], recommendation: 'System secure. Maintain standard monitoring.',
                rawHostObj: host
            });
            return;
        }
        host.risks.forEach(risk => {
            const sev = (risk.risk || 'Low');
            const severityOrder = { Critical: 1, High: 2, Medium: 3, Low: 4 }[sev] || 5;
            allTableRows.push({
                host: host.ip, hostname: host.hostname || '',
                severity: sev, severityOrder,
                cvss: risk.cvss || 0,
                ports: `Port ${risk.port}/${risk.protocol || 'tcp'} (${risk.service}${risk.product ? ` - ${risk.product}` : ''}${risk.version ? ` ${risk.version}` : ''})`,
                cves: risk.cves || [],
                recommendation: risk.recommendation || '',
                rawHostObj: host,
                rawRiskObj: risk
            });
        });
    });

    tableManager.setRows(allTableRows);
}

const tableManager = (() => {
    let rows         = [];
    let filtered     = [];
    let sortKey      = null;
    let sortDir      = 'asc';
    let severityF    = 'all';
    let searchQ      = '';
    let page         = 1;
    let pageSize     = 10;
    let searchTimer  = null;

    function setRows(r) { rows = r; page = 1; apply(); }

    function onSearch(q) {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => { searchQ = q.toLowerCase(); page = 1; apply(); }, 220);
    }

    function setSeverityFilter(sev) {
        severityF = sev; page = 1;
        document.querySelectorAll('.filter-pill').forEach(p => {
            const id = p.id.replace('pill-', '');
            p.classList.toggle('active', id === sev);
        });
        apply();
    }

    function sort(key) {
        if (sortKey === key) {
            sortDir = sortDir === 'asc' ? 'desc' : 'asc';
        } else {
            sortKey = key; sortDir = 'asc';
        }
        ['host', 'severity', 'cvss'].forEach(k => {
            const arrow = document.getElementById(`arrow-${k}`);
            const th    = document.getElementById(`th-${k}`);
            if (!arrow || !th) return;
            th.classList.remove('sort-asc', 'sort-desc');
            if (k === key) {
                arrow.textContent = sortDir === 'asc' ? '▲' : '▼';
                th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
            } else {
                arrow.textContent = '⇕';
            }
        });
        page = 1; apply();
    }

    function setPageSize(size) { pageSize = parseInt(size, 10); page = 1; apply(); }

    function apply() {
        filtered = rows.filter(r => {
            const matchSev = severityF === 'all' || r.severity.toLowerCase() === severityF;
            if (!matchSev) return false;
            if (!searchQ)  return true;
            const cveStr = r.cves.map(c => c.id).join(' ').toLowerCase();
            return (
                r.host.toLowerCase().includes(searchQ)           ||
                r.hostname.toLowerCase().includes(searchQ)       ||
                r.severity.toLowerCase().includes(searchQ)       ||
                r.ports.toLowerCase().includes(searchQ)          ||
                cveStr.includes(searchQ)                         ||
                r.recommendation.toLowerCase().includes(searchQ)
            );
        });

        if (sortKey) {
            filtered.sort((a, b) => {
                let va, vb;
                if (sortKey === 'host')     { va = a.host;          vb = b.host;          }
                if (sortKey === 'severity') { va = a.severityOrder; vb = b.severityOrder; }
                if (sortKey === 'cvss')     { va = a.cvss;          vb = b.cvss;          }
                if (va < vb) return sortDir === 'asc' ? -1 : 1;
                if (va > vb) return sortDir === 'asc' ?  1 : -1;
                return 0;
            });
        }

        render();
    }

    function render() {
        const tbody   = document.getElementById('scan-table-body');
        const countEl = document.getElementById('row-count-label');

        const total    = filtered.length;
        const start    = (page - 1) * pageSize;
        const pageRows = filtered.slice(start, start + pageSize);

        if (countEl) countEl.textContent = `Showing ${pageRows.length ? start + 1 : 0}–${Math.min(start + pageRows.length, total)} of ${total} result${total !== 1 ? 's' : ''}`;

        tbody.innerHTML = '';

        if (pageRows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:32px;">
                ${rows.length === 0 ? 'No scan data loaded yet.' : 'No results match your search or filter.'}
            </td></tr>`;
        } else {
            pageRows.forEach(r => {
                const tr = document.createElement('tr');
                const sevClass = r.severity.toLowerCase();

                // Format CVE pills with EPSS % and CISA KEV tags
                let cveContent = '<span style="color:var(--text-muted); font-size:12px;">None</span>';
                if (r.cves && r.cves.length > 0) {
                    cveContent = r.cves.map(c => {
                        const epssTag = c.epss !== undefined ? `<span class="epss-pill" title="EPSS Exploit Probability: ${(c.epss * 100).toFixed(1)}%">EPSS ${(c.epss * 100).toFixed(1)}%</span>` : '';
                        const kevTag  = c.isKev ? `<span class="kev-badge" title="CISA Known Exploited Vulnerability">CISA KEV</span>` : '';
                        return `<div style="margin-bottom:4px;"><span class="cve-pill" title="${c.description || ''}">${c.id}</span>${epssTag}${kevTag}</div>`;
                    }).join('');
                }

                // Remediation Column Action Button
                const actionBtn = r.rawHostObj && r.rawHostObj.risks && r.rawHostObj.risks.length > 0
                    ? `<div style="margin-top:6px;"><button class="btn-export" onclick="openRemediationModal('${r.host}')">🛡️ Get Remediation Script</button></div>`
                    : '';

                tr.innerHTML = `
                    <td>
                        <strong>${r.host}</strong>
                        ${r.hostname ? `<div style="font-size:11px; color:var(--text-secondary);">${r.hostname}</div>` : ''}
                    </td>
                    <td><span class="badge badge-${sevClass}">${r.severity}</span></td>
                    <td><strong>${r.cvss ? r.cvss.toFixed(1) : '0.0'}</strong></td>
                    <td style="font-size:13px;">${r.ports}</td>
                    <td>${cveContent}</td>
                    <td style="font-size:13px;">
                        <div>${r.recommendation}</div>
                        ${actionBtn}
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }

        renderPagination(total);
    }

    function renderPagination(total) {
        const bar      = document.getElementById('pagination-bar');
        const controls = document.getElementById('pagination-controls');
        if (!bar || !controls) return;

        const totalPages = Math.max(1, Math.ceil(total / pageSize));
        bar.style.display = total > 0 ? 'flex' : 'none';
        controls.innerHTML = '';

        const addBtn = (label, pg, isActive, disabled) => {
            const btn = document.createElement('button');
            btn.className = 'page-btn' + (isActive ? ' active' : '');
            btn.textContent = label;
            btn.disabled = disabled;
            btn.onclick = () => { page = pg; render(); };
            controls.appendChild(btn);
        };

        addBtn('‹', page - 1, false, page <= 1);
        const start = Math.max(1, page - 2);
        const end   = Math.min(totalPages, start + 4);
        if (start > 1)        { addBtn('1', 1, false, false); if (start > 2) addBtn('…', page, false, true); }
        for (let i = start; i <= end; i++) addBtn(i, i, i === page, false);
        if (end < totalPages) { if (end < totalPages - 1) addBtn('…', page, false, true); addBtn(totalPages, totalPages, false, false); }
        addBtn('›', page + 1, false, page >= totalPages);
    }

    return { setRows, onSearch, setSeverityFilter, sort, setPageSize, getFiltered: () => filtered };
})();

// ─────────────────────────────────────────────────────────────────────────────
// ── Remediation Script Generator Modal ─────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
function openRemediationModal(hostIp) {
    currentModalHost = hostIp;
    const hostObj    = currentReportData.details.find(h => h.ip === hostIp);
    currentModalRisks = hostObj ? (hostObj.risks || []) : [];

    document.getElementById('modal-target-host').textContent = hostIp;
    document.getElementById('remediation-modal').style.display = 'flex';
    switchScriptFormat('bash');
}

function closeRemediationModal() {
    document.getElementById('remediation-modal').style.display = 'none';
}

async function switchScriptFormat(fmt) {
    currentModalFormat = fmt;

    ['bash', 'ansible', 'powershell'].forEach(f => {
        const btn = document.getElementById(`fmt-${f}`);
        if (btn) btn.className = `format-btn ${f === fmt ? 'active' : ''}`;
    });

    const preview = document.getElementById('script-code-preview');
    preview.textContent = '# Generating remediation script payload…';

    try {
        const res  = await fetch('/api/remediation/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hostIp: currentModalHost, risks: currentModalRisks, format: fmt })
        });
        const data = await res.json();

        if (res.ok && data.script) {
            currentScriptText   = data.script;
            preview.textContent = data.script;
        } else {
            preview.textContent = `# Error generating script: ${data.error || 'Unknown error'}`;
        }
    } catch (e) {
        preview.textContent = `# Network error generating script: ${e.message}`;
    }
}

function downloadCurrentScript() {
    if (!currentScriptText) return;
    const ext = currentModalFormat === 'ansible' ? 'yml' : currentModalFormat === 'powershell' ? 'ps1' : 'sh';
    const filename = `vulnsight-hardening-${currentModalHost.replace(/[^a-zA-Z0-9]/g, '_')}.${ext}`;
    downloadText(currentScriptText, filename, 'text/plain');
    showToast('Script Downloaded', `Saved ${filename}`, 'success');
}

function copyCurrentScript() {
    if (!currentScriptText) return;
    navigator.clipboard.writeText(currentScriptText).then(() => {
        showToast('Copied', 'Remediation script copied to clipboard!', 'success');
    }).catch(err => {
        showToast('Copy Failed', err.message, 'error');
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Export Functions ──────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
function exportCSV() {
    const rows = tableManager.getFiltered();
    if (!rows || rows.length === 0) { showToast('Nothing to Export', 'No data rows to export. Load a scan first.', 'warning'); return; }

    const headers = ['Host IP', 'Hostname', 'Severity', 'CVSS', 'Ports & Services', 'CVEs', 'Remediation'];
    const csvRows = [headers.join(',')];

    rows.forEach(r => {
        const cveList = r.cves.map(c => c.id).join('; ');
        csvRows.push([
            `"${r.host}"`, `"${r.hostname}"`, `"${r.severity}"`,
            r.cvss ? r.cvss.toFixed(1) : '0.0',
            `"${r.ports.replace(/"/g, '""')}"`,
            `"${cveList}"`,
            `"${r.recommendation.replace(/"/g, '""')}"`
        ].join(','));
    });

    downloadText(csvRows.join('\n'), 'vulnsight-audit-report.csv', 'text/csv');
    showToast('Export Complete', `Exported ${rows.length} rows as CSV`, 'success');
}

function exportJSON() {
    const rows = tableManager.getFiltered();
    if (!rows || rows.length === 0) { showToast('Nothing to Export', 'No data rows to export. Load a scan first.', 'warning'); return; }

    const data = { exportedAt: new Date().toISOString(), totalRows: rows.length, rows };
    downloadText(JSON.stringify(data, null, 2), 'vulnsight-audit-report.json', 'application/json');
    showToast('Export Complete', `Exported ${rows.length} rows as JSON`, 'success');
}

function exportPDF() {
    if (!currentReportData) { showToast('Nothing to Export', 'No scan data loaded.', 'warning'); return; }
    showToast('Opening Print Dialog', 'Use your browser\'s print dialog to save as PDF.', 'info', 3000);
    setTimeout(() => window.print(), 500);
}

function downloadText(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}