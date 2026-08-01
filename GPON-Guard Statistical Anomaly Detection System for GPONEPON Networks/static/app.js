const REFRESH_MS = 2500;
const NUM_PORTS = 4;
const DOTS_PER_PORT = 10; // representative subset for the topology view (not all 128, for clarity)

let recentAlertOnus = new Set();     // onu_id -> has an unresolved-ish recent alert
let recentAlertSeverity = {};        // onu_id -> worst severity seen recently

function severityRank(s) {
  return { critical: 3, high: 2, medium: 1, low: 0 }[s] ?? 0;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  return res.json();
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function renderSummary(summary) {
  document.getElementById('s-onus').textContent = summary.total_onus;
  document.getElementById('s-alerts').textContent = summary.total_alerts;
  document.getElementById('s-critical').textContent = summary.critical;
}

function renderTelemetry(rows) {
  const tbody = document.getElementById('onu-tbody');
  tbody.innerHTML = '';
  rows
    .sort((a, b) => a.onu_id.localeCompare(b.onu_id))
    .forEach(r => {
      const sev = recentAlertSeverity[r.onu_id];
      let statusClass = 'status-ok', statusText = 'nominal';
      if (sev === 'critical') { statusClass = 'status-crit'; statusText = 'CRITICAL'; }
      else if (sev === 'high') { statusClass = 'status-crit'; statusText = 'alert'; }
      else if (sev === 'medium') { statusClass = 'status-warn'; statusText = 'drift'; }

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${r.onu_id}</td>
        <td>${r.serial}</td>
        <td>${r.rx_power}</td>
        <td>${r.temperature}</td>
        <td>${r.voltage}</td>
        <td>${r.traffic_mbps}</td>
        <td class="${statusClass}">${statusText}</td>
      `;
      tbody.appendChild(tr);
    });
  document.getElementById('telemetry-updated').textContent = 'updated ' + new Date().toLocaleTimeString();
}

function renderAlerts(alerts) {
  const feed = document.getElementById('alert-feed');
  recentAlertOnus = new Set();
  recentAlertSeverity = {};

  if (!alerts.length) {
    feed.innerHTML = '<div class="alert-empty">No alerts yet — monitoring nominal.</div>';
  } else {
    feed.innerHTML = '';
    alerts.forEach(a => {
      if (a.onu_id) {
        recentAlertOnus.add(a.onu_id);
        const prev = recentAlertSeverity[a.onu_id];
        if (!prev || severityRank(a.severity) > severityRank(prev)) {
          recentAlertSeverity[a.onu_id] = a.severity;
        }
      }
      const card = document.createElement('div');
      card.className = `alert-card sev-${a.severity}`;
      card.innerHTML = `
        <div class="alert-head">
          <span class="alert-type">${a.event_type}</span>
          <span>${fmtTime(a.ts)}</span>
        </div>
        <div class="alert-desc">${a.description}</div>
      `;
      feed.appendChild(card);
    });
  }
  document.getElementById('alert-updated').textContent = 'updated ' + new Date().toLocaleTimeString();
}

function buildTopologyOnuIds() {
  // representative subset per port for the visual, mirrors simulator.py's ID scheme
  const ids = [];
  for (let p = 1; p <= NUM_PORTS; p++) {
    for (let i = 1; i <= DOTS_PER_PORT; i++) {
      ids.push({ port: p, id: `PON${p}-ONU${i}` });
    }
  }
  return ids;
}

function renderTopology() {
  const svg = document.getElementById('topology-svg');
  const W = 900, H = 260;
  const oltX = 60, oltY = H / 2;
  const portXs = [180, 180, 180, 180];
  const portYs = [40, 100, 160, 220];
  const dotStartX = 300, dotEndX = 860;

  let parts = [];

  // OLT node
  parts.push(`<circle cx="${oltX}" cy="${oltY}" r="16" fill="none" stroke="var(--cyan)" stroke-width="2"/>`);
  parts.push(`<text x="${oltX}" y="${oltY + 34}" text-anchor="middle" fill="var(--muted)" font-family="IBM Plex Mono" font-size="10">OLT</text>`);

  const onus = buildTopologyOnuIds();

  for (let p = 0; p < NUM_PORTS; p++) {
    const py = portYs[p];
    // trunk line OLT -> port splitter
    parts.push(`<line x1="${oltX + 16}" y1="${oltY}" x2="${portXs[p]}" y2="${py}" stroke="#1E2A44" stroke-width="1.5"/>`);
    parts.push(`<circle cx="${portXs[p]}" cy="${py}" r="4" fill="var(--muted)"/>`);
    parts.push(`<text x="${portXs[p] - 10}" y="${py - 8}" text-anchor="end" fill="var(--muted)" font-family="IBM Plex Mono" font-size="9">PON${p + 1}</text>`);

    const portOnus = onus.filter(o => o.port === p + 1);
    portOnus.forEach((o, i) => {
      const x = dotStartX + (i * (dotEndX - dotStartX)) / (DOTS_PER_PORT - 1);
      parts.push(`<line x1="${portXs[p]}" y1="${py}" x2="${x}" y2="${py}" stroke="#141F38" stroke-width="1"/>`);

      let colorVar = 'var(--green)';
      const sev = recentAlertSeverity[o.id];
      if (sev === 'critical' || sev === 'high') colorVar = 'var(--red)';
      else if (sev === 'medium') colorVar = 'var(--amber)';

      parts.push(`<circle cx="${x}" cy="${py}" r="3.4" fill="${colorVar}"/>`);
    });
  }

  svg.innerHTML = parts.join('');
}

async function refreshAll() {
  try {
    const [summary, onus, alerts] = await Promise.all([
      fetchJSON('/api/summary'),
      fetchJSON('/api/onus'),
      fetchJSON('/api/alerts'),
    ]);
    renderAlerts(alerts);       // populate severity map first
    renderSummary(summary);
    renderTelemetry(onus);
    renderTopology();
  } catch (e) {
    console.error('refresh failed', e);
  }
}

refreshAll();
setInterval(refreshAll, REFRESH_MS);
