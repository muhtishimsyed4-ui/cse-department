/* ===================================================================
   NetGuard — app.js  (Phase 9: Full Interactivity)
   =================================================================== */

'use strict';

// ── State ────────────────────────────────────────────────────────────
let allDevices  = [];     // raw list from /api/devices
let modalMac    = null;   // MAC currently open in modal
let sortCol     = 'ip_address';
let sortDir     = 'asc';
let refreshTimer = null;

// ── Bootstrap modal instance ─────────────────────────────────────────
let bsModal = null;
document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('deviceModal');
  if (el) bsModal = new bootstrap.Modal(el);
  init();
});

// ===================================================================
// INIT & AUTO-REFRESH
// ===================================================================
function init() {
  fetchAll();
  setupSortHeaders();
  scheduleRefresh();
}

function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => { fetchAll(); scheduleRefresh(); }, 30_000);
}

function fetchAll() {
  fetchStats();
  fetchDevices();
  fetchHistory();
  fetchSchedulerStatus();
}

// ===================================================================
// STATS
// ===================================================================
async function fetchStats() {
  try {
    const data = await api('/api/stats');
    if (!data || typeof data !== 'object' || Array.isArray(data)) return;
    setText('statTotal',   data.total   ?? '—');
    setText('statOnline',  data.online  ?? '—');
    setText('statOffline', data.offline ?? '—');
    setText('statHigh',    data.risk_breakdown?.high   ?? '—');
    setText('statMedium',  data.risk_breakdown?.medium ?? '—');
    setText('statLow',     data.risk_breakdown?.low    ?? '—');
    setText('lastScanTime', data.last_scan
      ? new Date(data.last_scan).toLocaleTimeString()
      : 'Never');
  } catch (e) { console.warn('fetchStats error', e); }
}

// ===================================================================
// DEVICE TABLE
// ===================================================================
async function fetchDevices() {
  try {
    const data = await api('/api/devices');
    allDevices = Array.isArray(data) ? data : (data.devices || []);
    renderHighRiskSidebar();
    applyFilters();
  } catch (e) { console.warn('fetchDevices error', e); }
}

function applyFilters() {
  const search = (document.getElementById('searchInput')?.value || '').toLowerCase();
  const risk   = (document.getElementById('filterRisk')?.value  || '').toLowerCase();
  const status = (document.getElementById('filterStatus')?.value || '').toLowerCase();

  let filtered = allDevices.filter(d => {
    const matchSearch = !search || [
      d.ip_address, d.mac_address, d.vendor, d.friendly_name, d.hostname
    ].some(v => (v || '').toLowerCase().includes(search));

    const matchRisk   = !risk   || (d.risk_level  || '').toLowerCase() === risk;
    const matchStatus = !status ||
      (status === 'online'  &&  d.is_online) ||
      (status === 'offline' && !d.is_online) ||
      (status === 'new'     && d.status === 'new') ||
      (status === 'known'   && d.status === 'known');

    return matchSearch && matchRisk && matchStatus;
  });

  // sort
  filtered.sort((a, b) => {
    let av = (a[sortCol] || '').toString().toLowerCase();
    let bv = (b[sortCol] || '').toString().toLowerCase();
    if (sortCol === 'risk_level') {
      const order = { high: 0, medium: 1, low: 2, unknown: 3 };
      av = order[av] ?? 9; bv = order[bv] ?? 9;
    }
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ?  1 : -1;
    return 0;
  });

  renderTable(filtered);
  const total = allDevices.length;
  const shown = filtered.length;
  setText('deviceCount', shown === total ? `${total} device${total !== 1 ? 's' : ''}` : `${shown} / ${total}`);
}

function clearFilters() {
  const s = document.getElementById('searchInput');
  const r = document.getElementById('filterRisk');
  const st = document.getElementById('filterStatus');
  if (s)  s.value  = '';
  if (r)  r.value  = '';
  if (st) st.value = '';
  applyFilters();
}

function renderTable(devices) {
  const tbody = document.getElementById('deviceTableBody');
  if (!tbody) return;

  if (!devices.length) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center py-5 text-muted">
      <i class="bi bi-inbox fs-3 d-block mb-2"></i>No devices match the current filters</td></tr>`;
    return;
  }

  tbody.innerHTML = devices.map(d => {
    const risk    = (d.risk_level || 'unknown').toLowerCase();
    const online  = d.is_online ? true : false;
    const status  = online ? 'online' : 'offline';
    const name    = d.friendly_name || d.hostname || d.vendor || '—';
    const ports   = formatPortsInline(d.open_ports);
    const lastSeen = d.last_seen ? relativeTime(d.last_seen) : '—';
    const isOnline = d.is_online;

    return `<tr data-mac="${esc(d.mac_address)}" onclick="openModal('${esc(d.mac_address)}')">
      <td><span class="risk-dot risk-dot-${risk}"></span></td>
      <td class="font-monospace">${esc(d.ip_address || '—')}</td>
      <td class="font-monospace small text-muted">${esc(d.mac_address)}</td>
      <td>${esc(name)}</td>
      <td class="text-muted small">${esc(d.hostname || '—')}</td>
      <td><span class="badge badge-risk-${risk} rounded-pill">${risk.toUpperCase()}</span></td>
      <td><span class="badge badge-status-${status} rounded-pill">${status}</span></td>
      <td class="text-muted small">${lastSeen}</td>
      <td class="text-end row-actions" onclick="event.stopPropagation()">
        ${d.status === 'known'
          ? `<span class="btn btn-xs btn-success me-1 disabled" title="Already approved"><i class="bi bi-check-circle-fill"></i></span>`
          : `<button class="btn btn-xs btn-outline-success me-1" onclick="quickApprove('${esc(d.mac_address)}')" title="Approve"><i class="bi bi-check-lg"></i></button>`
        }
        <button class="btn btn-xs btn-outline-info me-1" onclick="quickSecScan('${esc(d.mac_address)}')" title="Security Scan">
          <i class="bi bi-shield-check"></i>
        </button>
        <button class="btn btn-xs btn-outline-danger" onclick="quickDelete('${esc(d.mac_address)}')" title="Delete">
          <i class="bi bi-trash3"></i>
        </button>
      </td>
    </tr>`;
  }).join('');
}

// ===================================================================
// SORT
// ===================================================================
function setupSortHeaders() {
  document.querySelectorAll('#deviceTable th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      if (sortCol === col) { sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }
      else { sortCol = col; sortDir = 'asc'; }

      document.querySelectorAll('#deviceTable th').forEach(h => {
        h.classList.remove('sort-asc', 'sort-desc');
      });
      th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
      applyFilters();
    });
  });
}

// ===================================================================
// DEVICE MODAL
// ===================================================================
async function openModal(mac) {
  modalMac = mac;
  try {
    const data = await api(`/api/devices/${encodeURIComponent(mac)}`);
    if (!data || !data.mac_address) { toast('Device not found', 'danger'); return; }
    const d = data;
    const risk = (d.risk_level || 'unknown').toLowerCase();
    const status = d.is_online ? 'online' : 'offline';
    const deviceStatus = d.status || 'new';

    // title + risk dot
    const dot = document.getElementById('modalRiskDot');
    if (dot) { dot.className = `risk-dot risk-dot-${risk}`; }
    setText('modalTitle', d.friendly_name || d.vendor || d.mac_address);

    // info table
    const infoTable = document.getElementById('modalInfoTable');
    if (infoTable) {
      infoTable.innerHTML = [
        ['IP Address',    `<span class="font-monospace">${esc(d.ip_address || '—')}</span>`],
        ['MAC Address',   `<span class="font-monospace small">${esc(d.mac_address)}</span>`],
        ['Vendor',        esc(d.vendor || '—')],
        ['Hostname',      esc(d.hostname || '—')],
        ['Custom Name',   esc(d.friendly_name || '—')],
        ['Online Status', `<span class="badge badge-status-${status}">${status}</span>`],
        ['Device Status', `<span class="badge ${deviceStatus === 'known' ? 'bg-success' : 'bg-warning text-dark'}">${deviceStatus.toUpperCase()}</span>`],
        ['Risk Level',    `<span class="badge badge-risk-${risk}">${risk.toUpperCase()}</span>`],
        ['First Seen',    esc(d.first_seen || '—')],
        ['Last Seen',     esc(d.last_seen  || '—')],
        ['Scanned At',    esc(d.last_security_scan || 'Not scanned')],
      ].map(([label, val]) =>
        `<tr><td class="text-muted small pe-3 fw-semibold" style="white-space:nowrap">${label}</td>
             <td class="small">${val}</td></tr>`
      ).join('');
    }

    // ports
    const portsEl = document.getElementById('modalPorts');
    if (portsEl) {
      portsEl.innerHTML = d.open_ports
        ? d.open_ports.split(',').map(p => `<span class="port-chip">${esc(p.trim())}</span>`).join(' ')
        : '<span class="text-muted">No open ports detected</span>';
    }

    // vulns
    const vulnsEl = document.getElementById('modalVulns');
    if (vulnsEl) {
      if (d.vulnerabilities) {
        const lines = d.vulnerabilities.split('\n').filter(l => l.trim());
        vulnsEl.innerHTML = lines.map(l => `<div class="mb-1">⚠ ${esc(l)}</div>`).join('');
      } else {
        vulnsEl.innerHTML = '<span class="text-muted">No vulnerabilities recorded</span>';
      }
    }

    // pre-fill rename input
    const ri = document.getElementById('renameInput');
    if (ri) ri.value = d.friendly_name || '';

    // approve button — hide if already known
    const approveBtn = document.getElementById('btnModalApprove');
    if (approveBtn) {
      if (d.status === 'known') {
        approveBtn.disabled = true;
        approveBtn.classList.remove('btn-outline-success');
        approveBtn.classList.add('btn-success');
        approveBtn.innerHTML = '<i class="bi bi-check-circle-fill"></i> Approved';
      } else {
        approveBtn.disabled = false;
        approveBtn.classList.add('btn-outline-success');
        approveBtn.classList.remove('btn-success');
        approveBtn.innerHTML = '<i class="bi bi-check-circle"></i> Approve';
      }
    }

    bsModal?.show();
  } catch (e) {
    console.error('openModal error', e);
    toast('Failed to load device details', 'danger');
  }
}

// ===================================================================
// MODAL ACTIONS
// ===================================================================
async function approveDevice() {
  if (!modalMac) return;
  const data = await api(`/api/devices/${encodeURIComponent(modalMac)}/approve`, 'POST');
  if (data.success) {
    toast('Device approved ✓', 'success');
    bsModal?.hide();
    fetchAll();
  } else {
    toast(data.message || 'Failed to approve device', 'danger');
  }
}

async function renameDevice() {
  if (!modalMac) return;
  const name = document.getElementById('renameInput')?.value?.trim();
  if (!name) { toast('Enter a name first', 'warning'); return; }
  const data = await api(`/api/devices/${encodeURIComponent(modalMac)}/name`, 'PUT', { name });
  if (data.success) {
    toast(`Renamed to "${name}" ✓`, 'success');
    setText('modalTitle', name);
    fetchDevices();
  } else {
    toast(data.message || 'Rename failed', 'danger');
  }
}

async function securityScan() {
  if (!modalMac) return;
  toast('Security scan started…', 'info');
  const data = await api(`/api/scan/security/${encodeURIComponent(modalMac)}`);
  if (data.success) {
    toast(`Scan done: ${(data.risk_level || '').toUpperCase()} risk (score ${data.risk_score ?? 0})`, 'success');
    openModal(modalMac);   // refresh modal with new data
    fetchStats();
  } else {
    toast(data.message || 'Security scan failed', 'danger');
  }
}

async function deleteDevice() {
  if (!modalMac) return;
  if (!confirm('Delete this device from the database?')) return;
  const data = await api(`/api/devices/${encodeURIComponent(modalMac)}`, 'DELETE');
  if (data.success) {
    toast('Device deleted', 'success');
    bsModal?.hide();
    fetchAll();
  } else {
    toast(data.message || 'Delete failed', 'danger');
  }
}

// ───────────── Quick-action buttons in table rows ─────────────────────
async function quickApprove(mac) {
  const data = await api(`/api/devices/${encodeURIComponent(mac)}/approve`, 'POST');
  if (data.success) { toast('Device approved ✓', 'success'); fetchAll(); }
  else toast(data.message || 'Failed', 'danger');
}

async function quickSecScan(mac) {
  toast('Security scan started…', 'info');
  const data = await api(`/api/scan/security/${encodeURIComponent(mac)}`);
  if (data.success) { toast('Scan complete ✓', 'success'); fetchAll(); }
  else toast(data.message || 'Scan failed', 'danger');
}

async function quickDelete(mac) {
  if (!confirm('Delete this device?')) return;
  const data = await api(`/api/devices/${encodeURIComponent(mac)}`, 'DELETE');
  if (data.success) { toast('Device deleted', 'success'); fetchAll(); }
  else toast(data.message || 'Delete failed', 'danger');
}

// ===================================================================
// MANUAL SCAN
// ===================================================================
async function triggerScan() {
  const btn = document.getElementById('btnScan');
  const overlay = document.getElementById('scanOverlay');

  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Scanning…'; }
  if (overlay) overlay.classList.remove('d-none');

  try {
    const data = await api('/api/scan');
    if (data.success) {
      toast(`Scan complete — ${data.devices_found} device(s), ${data.new_devices} new`, 'success');
      fetchAll();
    } else {
      toast(data.message || 'Scan failed', 'danger');
    }
  } catch (e) {
    toast('Scan request failed', 'danger');
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-wifi"></i> Scan Now'; }
    if (overlay) overlay.classList.add('d-none');
  }
}

// ===================================================================
// SCHEDULER
// ===================================================================
async function fetchSchedulerStatus() {
  try {
    const data = await api('/api/scheduler/status');
    const running = data.scheduler_running;
    const paused  = data.scheduler_paused;
    const job     = data.jobs?.[0];

    const pillEl  = document.getElementById('schedulerPill');
    const pillTxt = document.getElementById('schedulerPillText');
    const statusEl = document.getElementById('schedulerStatus');
    const nextEl   = document.getElementById('schedulerNext');

    if (paused) {
      if (pillEl)  { pillEl.className = 'badge rounded-pill bg-warning text-dark'; }
      if (pillTxt) pillTxt.textContent = 'Paused';
      if (statusEl){ statusEl.className = 'badge bg-warning text-dark'; statusEl.textContent = 'Paused'; }
    } else if (running) {
      if (pillEl)  { pillEl.className = 'badge rounded-pill bg-success'; }
      if (pillTxt) pillTxt.textContent = 'Auto-scan active';
      if (statusEl){ statusEl.className = 'badge bg-success'; statusEl.textContent = 'Running'; }
    } else {
      if (pillEl)  { pillEl.className = 'badge rounded-pill bg-secondary'; }
      if (pillTxt) pillTxt.textContent = 'Scheduler off';
      if (statusEl){ statusEl.className = 'badge bg-secondary'; statusEl.textContent = 'Off'; }
    }

    if (nextEl && job?.next_run) {
      const next = new Date(job.next_run);
      nextEl.textContent = next.toLocaleTimeString();
    } else if (nextEl) {
      nextEl.textContent = '—';
    }
  } catch (e) { console.warn('fetchSchedulerStatus error', e); }
}

async function pauseScheduler() {
  const data = await api('/api/scheduler/pause', 'POST');
  toast(data.message || 'Scheduler paused', data.success ? 'warning' : 'danger');
  fetchSchedulerStatus();
}

async function resumeScheduler() {
  const data = await api('/api/scheduler/resume', 'POST');
  toast(data.message || 'Scheduler resumed', data.success ? 'success' : 'danger');
  fetchSchedulerStatus();
}

// ===================================================================
// SCAN HISTORY
// ===================================================================
async function fetchHistory() {
  try {
    const data = await api('/api/scan/history?limit=8');
    const list = document.getElementById('scanHistoryList');
    if (!list) return;
    const history = Array.isArray(data) ? data : (data.history || []);
    if (!history.length) {
      list.innerHTML = '<li class="list-group-item text-muted small">No scan history yet</li>';
      return;
    }
    list.innerHTML = history.map(h => {
      const t = h.scan_time ? new Date(h.scan_time).toLocaleTimeString() : '—';
      const date = h.scan_time ? new Date(h.scan_time).toLocaleDateString() : '';
      return `<li class="list-group-item list-group-item-action px-3 py-2">
        <div class="d-flex justify-content-between">
          <span class="small fw-semibold">${date} ${t}</span>
          <span class="badge bg-secondary">${h.devices_found ?? 0} devices</span>
        </div>
        <div class="mt-1 small text-muted">
          ${h.new_devices ?? 0} new &nbsp;·&nbsp;
          <span class="${(h.high_risk_devices ?? 0) > 0 ? 'text-danger fw-semibold' : ''}">${h.high_risk_devices ?? 0} high-risk</span>
          <span class="ms-2 text-muted fst-italic">${h.triggered_by || ''}</span>
        </div>
      </li>`;
    }).join('');
  } catch (e) { console.warn('fetchHistory error', e); }
}

// ===================================================================
// HIGH-RISK SIDEBAR
// ===================================================================
function renderHighRiskSidebar() {
  const list = document.getElementById('highRiskList');
  if (!list) return;
  const highs = allDevices.filter(d => (d.risk_level || '').toUpperCase() === 'HIGH');
  if (!highs.length) {
    list.innerHTML = '<li class="list-group-item text-muted small">No high-risk devices 🎉</li>';
    return;
  }
  list.innerHTML = highs.map(d =>
    `<li class="list-group-item list-group-item-action px-3 py-2 list-group-item-danger"
         onclick="openModal('${esc(d.mac_address)}')" style="cursor:pointer">
       <div class="fw-semibold small">${esc(d.friendly_name || d.vendor || d.ip_address)}</div>
       <div class="small text-muted font-monospace">${esc(d.ip_address)} · ${esc(d.mac_address)}</div>
     </li>`
  ).join('');
}

// ===================================================================
// UTILS
// ===================================================================
async function api(url, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  return res.json();
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatPortsInline(ports) {
  if (!ports) return '<span class="text-muted small">—</span>';
  return ports.split(',').slice(0, 4).map(p =>
    `<span class="port-chip">${esc(p.trim())}</span>`
  ).join('') + (ports.split(',').length > 4 ? '…' : '');
}

function relativeTime(isoStr) {
  if (!isoStr) return '—';
  const diff = Date.now() - new Date(isoStr).getTime();
  if (diff < 60_000)           return 'just now';
  if (diff < 3_600_000)        return `${Math.floor(diff/60_000)}m ago`;
  if (diff < 86_400_000)       return `${Math.floor(diff/3_600_000)}h ago`;
  return `${Math.floor(diff/86_400_000)}d ago`;
}

function toast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const colorMap = {
    success: 'bg-success text-white',
    danger:  'bg-danger  text-white',
    warning: 'bg-warning text-dark',
    info:    'bg-info    text-white',
  };
  const iconMap = {
    success: 'bi-check-circle-fill',
    danger:  'bi-x-circle-fill',
    warning: 'bi-exclamation-triangle-fill',
    info:    'bi-info-circle-fill',
  };

  const id = 'toast-' + Date.now();
  const div = document.createElement('div');
  div.id = id;
  div.className = `toast align-items-center border-0 ${colorMap[type] || colorMap.info}`;
  div.setAttribute('role', 'alert');
  div.innerHTML = `
    <div class="d-flex">
      <div class="toast-body d-flex align-items-center gap-2">
        <i class="bi ${iconMap[type] || iconMap.info}"></i>
        ${esc(message)}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>`;

  container.appendChild(div);
  const t = new bootstrap.Toast(div, { delay: 4000 });
  t.show();
  div.addEventListener('hidden.bs.toast', () => div.remove());
}
