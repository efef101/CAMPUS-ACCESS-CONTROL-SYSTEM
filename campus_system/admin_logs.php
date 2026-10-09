<?php
session_start();
include 'db.php';

if (!isset($_SESSION['admin_logged_in'])) {
  header("Location: admin_login.php");
  exit;
}

$result = $conn->query("SELECT * FROM logs ORDER BY timestamp DESC");
$logs = [];
while ($row = $result->fetch_assoc()) {
  $logs[] = $row;
}
$logsJson = json_encode($logs);
?>

<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Admin - Access Logs</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700&display=swap');

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Syne', sans-serif;
      background: #fafbfd;
      min-height: 100vh;
      color: #16233d;
      display: flex;
    }

    /* SIDEBAR */
    .sidebar {
      width: 80px;
      background: linear-gradient(180deg, #1c3a5e, #0f2440);
      border-right: 1px solid #0f2440;
      height: 100vh;
      position: sticky;
      top: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 24px 0;
      gap: 12px;
      flex-shrink: 0;
    }

    .sidebar .logo img {
      width: 44px;
      height: 44px;
      border-radius: 12px;
      object-fit: cover;
      border: 1px solid rgba(255,255,255,0.25);
    }

    .sidebar-divider {
      width: 40px;
      height: 1px;
      background: rgba(255,255,255,0.12);
      margin: 4px 0;
    }

    .sidebar .nav-item {
      width: 44px;
      height: 44px;
      border-radius: 12px;
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.12);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      cursor: pointer;
      transition: background 0.2s;
      text-decoration: none;
    }

    .sidebar .nav-item:hover {
      background: rgba(255,255,255,0.16);
    }

    .sidebar .nav-item.active {
      background: rgba(255,255,255,0.22);
      border-color: rgba(255,255,255,0.35);
    }

    .sidebar .logout-item {
      margin-top: auto;
    }

    /* MAIN */
    .main {
      flex: 1;
      padding: 30px 20px;
      overflow-x: hidden;
    }

    h2 {
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0.05em;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 10px;
      color: #16233d;
    }

    .filters {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 20px;
    }

    .filters input, .filters select {
      background: #ffffff;
      border: 1px solid #dce4ef;
      border-radius: 10px;
      color: #16233d;
      font-family: 'Syne', sans-serif;
      font-size: 13px;
      padding: 9px 14px;
      outline: none;
      transition: border 0.2s;
      flex: 1;
      min-width: 140px;
    }

    .filters input::placeholder { color: #9aa9c2; }
    .filters input:focus, .filters select:focus { border-color: #1c3a5e; }
    .filters select option { background: #ffffff; }

    .filters button {
      background: #ffffff;
      border: 1px solid #dce4ef;
      border-radius: 10px;
      color: #6b7a94;
      font-family: 'Syne', sans-serif;
      font-size: 13px;
      padding: 9px 16px;
      cursor: pointer;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .filters button:hover { background: #eef3fa; color: #16233d; }

    .stats {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .stat {
      background: #ffffff;
      border: 1px solid #dce4ef;
      border-radius: 12px;
      padding: 12px 18px;
      flex: 1;
      min-width: 100px;
      text-align: center;
      box-shadow: 0 1px 3px rgba(22,58,94,0.05);
    }

    .stat-num {
      font-family: 'JetBrains Mono', monospace;
      font-size: 22px;
      font-weight: 600;
    }

    .stat-label {
      font-size: 11px;
      color: #8a9bb5;
      margin-top: 2px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .stat-num.entries { color: #16a34a; }
    .stat-num.exits   { color: #dc2626; }
    .stat-num.total   { color: #1c3a5e; }
    .stat-num.denied  { color: #d97706; }

    /* ===== REPORT PANEL ===== */
    .report-bar {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }

    .report-bar button {
      background: #eef3fa;
      border: 1px solid #c7d7ec;
      border-radius: 10px;
      color: #1c3a5e;
      font-family: 'Syne', sans-serif;
      font-size: 13px;
      padding: 9px 18px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .report-bar button:hover {
      background: #dfeaf7;
    }
    .report-bar button.active {
      background: #dfeaf7;
      border-color: #1c3a5e;
    }

    .export-btn {
      background: #e8f8ef !important;
      border: 1px solid #b8ebc9 !important;
      color: #16a34a !important;
      margin-left: auto;
    }
    .export-btn:hover {
      background: #d7f4e3 !important;
    }

    #reportPanel {
      display: none;
      margin-bottom: 24px;
    }
    #reportPanel.open { display: block; }

    /* Report options */
    .report-options {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 16px;
      padding: 16px;
      background: #ffffff;
      border: 1px solid #dce4ef;
      border-radius: 12px;
    }

    .report-options label {
      display: flex;
      align-items: center;
      gap: 7px;
      font-size: 13px;
      color: #4a5b78;
      cursor: pointer;
      padding: 6px 12px;
      border-radius: 8px;
      border: 1px solid #dce4ef;
      transition: all 0.2s;
    }
    .report-options label:hover { background: #f4f7fb; }
    .report-options input[type="checkbox"] { accent-color: #1c3a5e; width: 14px; height: 14px; }
    .report-options input[type="checkbox"]:checked + span { color: #1c3a5e; }

    .chart-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 16px;
      margin-bottom: 16px;
    }

    .chart-card {
      background: #ffffff;
      border: 1px solid #dce4ef;
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 1px 3px rgba(22,58,94,0.05);
    }

    .chart-card h3 {
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #8a9bb5;
      margin-bottom: 16px;
    }

    .chart-card canvas { max-height: 220px; }

    /* Percentage breakdown table */
    .pct-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-top: 8px;
    }
    .pct-table th {
      text-align: left;
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #96a6c0;
      padding: 6px 10px;
      font-weight: 600;
    }
    .pct-table td {
      padding: 7px 10px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #3c4a63;
      border-top: 1px solid #eef2f8;
    }
    .pct-bar-wrap {
      background: #eef2f8;
      border-radius: 4px;
      height: 6px;
      width: 100px;
      overflow: hidden;
      display: inline-block;
      vertical-align: middle;
      margin-left: 8px;
    }
    .pct-bar {
      height: 100%;
      border-radius: 4px;
    }

    /* Failed attempts card */
    .failed-card {
      background: #fffaf0;
      border: 1px solid #f6e2b3;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 16px;
    }
    .failed-card h3 {
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #d97706;
      margin-bottom: 14px;
      opacity: 0.9;
    }
    .failed-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 200px;
      overflow-y: auto;
    }
    .failed-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 12px;
      background: #fff3da;
      border-radius: 8px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
    }
    .failed-row .fname { font-family: 'Syne', sans-serif; font-size: 13px; color: #16233d; }
    .failed-row .ftime { color: #9aa9c2; font-size: 11px; }
    .failed-count {
      background: #fbe6b8;
      border: 1px solid #f0cd82;
      color: #b4650a;
      border-radius: 6px;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 600;
    }

    /* ===== TABLE ===== */
    .table-wrap {
      background: #ffffff;
      border: 1px solid #dce4ef;
      border-radius: 14px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(22,58,94,0.05);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    thead tr { background: #f4f7fb; }

    th {
      padding: 12px 16px;
      text-align: left;
      font-size: 11px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: #8a9bb5;
      font-weight: 600;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }

    th:hover { color: #16233d; }
    th .sort-icon { margin-left: 4px; opacity: 0.4; }
    th.active .sort-icon { opacity: 1; color: #1c3a5e; }

    tbody tr {
      border-top: 1px solid #eef2f8;
      transition: background 0.15s;
    }
    tbody tr:hover { background: #f7fafd; }

    td {
      padding: 11px 16px;
      color: #3c4a63;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }

    td.name-col {
      font-family: 'Syne', sans-serif;
      font-size: 13px;
      font-weight: 600;
      color: #16233d;
    }

    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.05em;
      font-family: 'Syne', sans-serif;
    }

    .badge.entry  { background: #e8f8ef; color: #16a34a; border: 1px solid #bdeccf; }
    .badge.exit   { background: #fdeaea; color: #dc2626; border: 1px solid #f6c6c6; }
    .badge.denied { background: #fdf1d8; color: #d97706; border: 1px solid #f0d79a; }

    .role-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 11px;
      background: #eef3fa;
      color: #1c3a5e;
      border: 1px solid #c7d7ec;
      font-family: 'Syne', sans-serif;
    }

    .no-results {
      padding: 40px;
      text-align: center;
      color: #b7c3d6;
      font-size: 14px;
    }

    .pagination {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      border-top: 1px solid #eef2f8;
      font-size: 12px;
      color: #8a9bb5;
      flex-wrap: wrap;
      gap: 10px;
    }

    .page-btns { display: flex; gap: 6px; flex-wrap: wrap; }

    .page-btns button {
      background: #f4f7fb;
      border: 1px solid #dce4ef;
      border-radius: 7px;
      color: #6b7a94;
      font-size: 12px;
      padding: 5px 12px;
      cursor: pointer;
      transition: all 0.15s;
      font-family: 'Syne', sans-serif;
    }

    .page-btns button:hover:not(:disabled) { background: #eef3fa; color: #16233d; }
    .page-btns button:disabled { opacity: 0.4; cursor: default; }
    .page-btns button.active {
      background: #dfeaf7;
      border-color: #1c3a5e;
      color: #1c3a5e;
    }

    .back { margin-top: 20px; text-align: center; }
    .back a {
      text-decoration: none;
      font-size: 13px;
      color: #8a9bb5;
      transition: color 0.2s;
    }
    .back a:hover { color: #16233d; }

    /* PDF export loading */
    #exportingMsg {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(22,35,61,0.55);
      backdrop-filter: blur(6px);
      z-index: 9999;
      justify-content: center;
      align-items: center;
      flex-direction: column;
      gap: 12px;
      font-size: 14px;
      color: #ffffff;
    }
    #exportingMsg.show { display: flex; }
    .spinner {
      width: 32px; height: 32px;
      border: 3px solid rgba(255,255,255,0.2);
      border-top-color: #ffffff;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="logo"><img src="logo.png" alt="logo"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="admin_dashboard.php" title="Dashboard">🏠</a>
  <a class="nav-item" href="users.php" title="Users">👤</a>
  <a class="nav-item" href="admin_add_security.php" title="Security Accounts">🔐</a>
  <a class="nav-item active" href="admin_logs.php" title="Logs">📋</a>
  <a class="nav-item logout-item" href="logout.php" title="Logout">🚪</a>
</div>

<!-- MAIN -->
<div class="main">

<!-- Export loading overlay -->
<div id="exportingMsg">
  <div class="spinner"></div>
  <span>Generating PDF...</span>
</div>

<h2>📊 Access Logs</h2>

<!-- Filters -->
<div class="filters">
  <input type="text"  id="searchName"  placeholder="🔍 Search name or ID..." oninput="applyFilters()">
  <select id="filterRole" onchange="applyFilters()">
    <option value="">All Roles</option>
    <option value="student">Student</option>
    <option value="faculty">Faculty</option>
    <option value="staff">Staff</option>
    <option value="visitor">Visitor</option>
    <option value="alumni">Alumni</option>
  </select>
  <select id="filterType" onchange="applyFilters()">
    <option value="">All Types</option>
    <option value="ENTRY">Entry</option>
    <option value="EXIT">Exit</option>
    <option value="DENIED">Denied</option>
  </select>
  <input type="date" id="filterDate" onchange="applyFilters()">
  <button onclick="clearFilters()">✕ Clear</button>
</div>

<!-- Stats -->
<div class="stats">
  <div class="stat">
    <div class="stat-num total"   id="statTotal">0</div>
    <div class="stat-label">Total</div>
  </div>
  <div class="stat">
    <div class="stat-num entries" id="statEntries">0</div>
    <div class="stat-label">Entries</div>
  </div>
  <div class="stat">
    <div class="stat-num exits"   id="statExits">0</div>
    <div class="stat-label">Exits</div>
  </div>
  <div class="stat">
    <div class="stat-num denied"  id="statDenied">0</div>
    <div class="stat-label">Denied</div>
  </div>
</div>

<!-- Report toggle bar -->
<div class="report-bar">
  <button id="reportToggleBtn" onclick="toggleReport()">📈 Generate Report</button>
  <button class="export-btn" onclick="exportPDF()">⬇ Export PDF</button>
</div>

<!-- Report panel -->
<div id="reportPanel">

  <!-- What to include -->
  <div class="report-options">
    <label><input type="checkbox" id="optOverview"  checked onchange="buildCharts()"><span>Overview Chart</span></label>
    <label><input type="checkbox" id="optRole"      checked onchange="buildCharts()"><span>By Role</span></label>
    <label><input type="checkbox" id="optHourly"    checked onchange="buildCharts()"><span>Hourly Activity</span></label>
    <label><input type="checkbox" id="optDaily"     checked onchange="buildCharts()"><span>Daily Trend</span></label>
    <label><input type="checkbox" id="optPct"       checked onchange="buildCharts()"><span>Percentages</span></label>
    <label><input type="checkbox" id="optFailed"    checked onchange="buildCharts()"><span>Failed Attempts</span></label>
  </div>

  <!-- Charts grid -->
  <div class="chart-grid" id="chartGrid"></div>

  <!-- Failed attempts -->
  <div class="failed-card" id="failedCard"></div>

</div>

<!-- Table -->
<div class="table-wrap" id="logTableWrap">
  <table>
    <thead>
      <tr>
        <th onclick="sortBy('id_number')">ID <span class="sort-icon">↕</span></th>
        <th onclick="sortBy('name')">Name <span class="sort-icon">↕</span></th>
        <th onclick="sortBy('role')">Role <span class="sort-icon">↕</span></th>
        <th onclick="sortBy('status')">Status <span class="sort-icon">↕</span></th>
        <th onclick="sortBy('type')">Type <span class="sort-icon">↕</span></th>
        <th onclick="sortBy('timestamp')">Time <span class="sort-icon">↕</span></th>
      </tr>
    </thead>
    <tbody id="logsBody"></tbody>
  </table>
  <div class="pagination">
    <span id="pageInfo">Showing 0 results</span>
    <div class="page-btns" id="pageBtns"></div>
  </div>
</div>

<div class="back">
  <a href="admin_dashboard.php">← Back to Dashboard</a>
</div>

</div>
<!-- /.main -->

<script>
const allLogs = <?= $logsJson ?>;

let filtered  = [...allLogs];
let sortKey   = 'timestamp';
let sortDir   = -1;
let page      = 1;
const perPage = 10;

let chartInstances = {};
let reportOpen = false;

/* ===== FILTERS ===== */
function applyFilters() {
  const name = document.getElementById('searchName').value.toLowerCase().trim();
  const role = document.getElementById('filterRole').value.toLowerCase();
  const type = document.getElementById('filterType').value.toUpperCase();
  const date = document.getElementById('filterDate').value;

  filtered = allLogs.filter(r => {
    const rowName = (r.name || '').toLowerCase();
    const rowId   = (r.id_number || '').toString().toLowerCase();
    const matchName = !name || rowName.includes(name) || rowId.includes(name);
    const matchRole = !role || (r.role || '').toLowerCase() === role;
    const matchType = !type || (r.type || '').toUpperCase() === type;
    const matchDate = !date || (r.timestamp || '').startsWith(date);
    return matchName && matchRole && matchType && matchDate;
  });

  page = 1;
  render();
  if (reportOpen) buildCharts();
}

function clearFilters() {
  document.getElementById('searchName').value = '';
  document.getElementById('filterRole').value = '';
  document.getElementById('filterType').value = '';
  document.getElementById('filterDate').value = '';
  filtered = [...allLogs];
  page = 1;
  render();
  if (reportOpen) buildCharts();
}

/* ===== SORT ===== */
function sortBy(key) {
  if (sortKey === key) sortDir *= -1;
  else { sortKey = key; sortDir = -1; }
  filtered.sort((a, b) => a[key] > b[key] ? sortDir : -sortDir);
  document.querySelectorAll('th').forEach(th => th.classList.remove('active'));
  render();
}

/* ===== RENDER TABLE ===== */
function render() {
  const start = (page - 1) * perPage;
  const rows  = filtered.slice(start, start + perPage);
  const body  = document.getElementById('logsBody');

  const entries = filtered.filter(r => r.type === 'ENTRY').length;
  const exits   = filtered.filter(r => r.type === 'EXIT').length;
  const denied  = filtered.filter(r => r.type === 'DENIED').length;

  document.getElementById('statTotal').textContent   = filtered.length;
  document.getElementById('statEntries').textContent = entries;
  document.getElementById('statExits').textContent   = exits;
  document.getElementById('statDenied').textContent  = denied;

  if (rows.length === 0) {
    body.innerHTML = `<tr><td colspan="6"><div class="no-results">No logs found</div></td></tr>`;
  } else {
    body.innerHTML = rows.map(r => {
      const typeClass = r.type === 'ENTRY' ? 'entry' : r.type === 'EXIT' ? 'exit' : 'denied';
      return `<tr>
        <td>${r.id_number}</td>
        <td class="name-col">${r.name}</td>
        <td><span class="role-badge">${r.role}</span></td>
        <td>${r.status}</td>
        <td><span class="badge ${typeClass}">${r.type}</span></td>
        <td>${r.timestamp}</td>
      </tr>`;
    }).join('');
  }

  const totalPages = Math.ceil(filtered.length / perPage);
  const showing    = filtered.length === 0 ? 0 : start + 1;
  document.getElementById('pageInfo').textContent =
    `Showing ${showing}–${Math.min(start + perPage, filtered.length)} of ${filtered.length}`;

  const btns = document.getElementById('pageBtns');
  let btnHtml = `<button onclick="goPage(${page-1})" ${page===1?'disabled':''}>‹ Prev</button>`;
  for (let i = 1; i <= totalPages; i++) {
    btnHtml += `<button class="${i===page?'active':''}" onclick="goPage(${i})">${i}</button>`;
  }
  btnHtml += `<button onclick="goPage(${page+1})" ${page===totalPages||totalPages===0?'disabled':''}>Next ›</button>`;
  btns.innerHTML = btnHtml;
}

function goPage(p) {
  const totalPages = Math.ceil(filtered.length / perPage);
  if (p < 1 || p > totalPages) return;
  page = p;
  render();
}

/* ===== REPORT ===== */
function toggleReport() {
  const panel = document.getElementById('reportPanel');
  const btn   = document.getElementById('reportToggleBtn');
  reportOpen  = !reportOpen;
  panel.classList.toggle('open', reportOpen);
  btn.classList.toggle('active', reportOpen);
  btn.textContent = reportOpen ? '✕ Close Report' : '📈 Generate Report';
  if (reportOpen) buildCharts();
}

function opt(id) { return document.getElementById(id).checked; }

function destroyChart(id) {
  if (chartInstances[id]) {
    chartInstances[id].destroy();
    delete chartInstances[id];
  }
}

function buildCharts() {
  const data   = filtered;
  const total  = data.length;
  const entries = data.filter(r => r.type === 'ENTRY').length;
  const exits   = data.filter(r => r.type === 'EXIT').length;
  const denied  = data.filter(r => r.type === 'DENIED').length;

  /* --- Overview donut --- */
  const grid = document.getElementById('chartGrid');
  grid.innerHTML = '';

  Object.keys(chartInstances).forEach(k => { chartInstances[k].destroy(); });
  chartInstances = {};

  // ---- OVERVIEW DONUT ----
  if (opt('optOverview')) {
    grid.insertAdjacentHTML('beforeend', `
      <div class="chart-card" id="cardOverview">
        <h3>Overview — Entry / Exit / Denied</h3>
        <canvas id="chartOverview"></canvas>
      </div>`);
    chartInstances.overview = new Chart(
      document.getElementById('chartOverview'), {
        type: 'doughnut',
        data: {
          labels: ['Entry','Exit','Denied'],
          datasets: [{ data: [entries, exits, denied],
            backgroundColor: ['rgba(22,163,74,0.75)','rgba(220,38,38,0.75)','rgba(217,119,6,0.75)'],
            borderWidth: 0
          }]
        },
        options: {
          plugins: { legend: { labels: { color: '#16233d', font: { family: 'Syne' } } } }
        }
      }
    );
  }

  // ---- BY ROLE BAR ----
  if (opt('optRole')) {
    const roles = {};
    data.forEach(r => {
      const role = r.role || 'unknown';
      if (!roles[role]) roles[role] = { ENTRY: 0, EXIT: 0, DENIED: 0 };
      roles[role][r.type] = (roles[role][r.type] || 0) + 1;
    });
    const roleLabels = Object.keys(roles);

    grid.insertAdjacentHTML('beforeend', `
      <div class="chart-card" id="cardRole">
        <h3>Activity by Role</h3>
        <canvas id="chartRole"></canvas>
      </div>`);
    chartInstances.role = new Chart(
      document.getElementById('chartRole'), {
        type: 'bar',
        data: {
          labels: roleLabels,
          datasets: [
            { label: 'Entry',  data: roleLabels.map(r => roles[r].ENTRY),  backgroundColor: 'rgba(22,163,74,0.65)' },
            { label: 'Exit',   data: roleLabels.map(r => roles[r].EXIT),   backgroundColor: 'rgba(220,38,38,0.65)' },
            { label: 'Denied', data: roleLabels.map(r => roles[r].DENIED), backgroundColor: 'rgba(217,119,6,0.65)' }
          ]
        },
        options: {
          plugins: { legend: { labels: { color: '#16233d', font: { family: 'Syne' } } } },
          scales: {
            x: { ticks: { color: '#6b7a94' }, grid: { color: '#eef2f8' } },
            y: { ticks: { color: '#6b7a94' }, grid: { color: '#eef2f8' }, beginAtZero: true }
          }
        }
      }
    );
  }

  // ---- HOURLY LINE ----
  if (opt('optHourly')) {
    const hours = Array(24).fill(0).map(() => ({ ENTRY: 0, EXIT: 0, DENIED: 0 }));
    data.forEach(r => {
      const h = new Date(r.timestamp).getHours();
      if (!isNaN(h)) hours[h][r.type] = (hours[h][r.type] || 0) + 1;
    });
    const hourLabels = Array.from({length: 24}, (_, i) => `${String(i).padStart(2,'0')}:00`);

    grid.insertAdjacentHTML('beforeend', `
      <div class="chart-card" id="cardHourly">
        <h3>Hourly Activity</h3>
        <canvas id="chartHourly"></canvas>
      </div>`);
    chartInstances.hourly = new Chart(
      document.getElementById('chartHourly'), {
        type: 'line',
        data: {
          labels: hourLabels,
          datasets: [
            { label: 'Entry',  data: hours.map(h => h.ENTRY),  borderColor: '#16a34a', backgroundColor: 'rgba(22,163,74,0.08)', tension: 0.4, fill: true },
            { label: 'Exit',   data: hours.map(h => h.EXIT),   borderColor: '#dc2626', backgroundColor: 'rgba(220,38,38,0.08)', tension: 0.4, fill: true },
            { label: 'Denied', data: hours.map(h => h.DENIED), borderColor: '#d97706', backgroundColor: 'rgba(217,119,6,0.08)', tension: 0.4, fill: true }
          ]
        },
        options: {
          plugins: { legend: { labels: { color: '#16233d', font: { family: 'Syne' } } } },
          scales: {
            x: { ticks: { color: '#8a9bb5', maxTicksLimit: 12 }, grid: { color: '#eef2f8' } },
            y: { ticks: { color: '#8a9bb5' }, grid: { color: '#eef2f8' }, beginAtZero: true }
          }
        }
      }
    );
  }

  // ---- DAILY TREND ----
  if (opt('optDaily')) {
    const days = {};
    data.forEach(r => {
      const d = (r.timestamp || '').slice(0, 10);
      if (!d) return;
      if (!days[d]) days[d] = { ENTRY: 0, EXIT: 0, DENIED: 0 };
      days[d][r.type] = (days[d][r.type] || 0) + 1;
    });
    const dayLabels = Object.keys(days).sort();

    grid.insertAdjacentHTML('beforeend', `
      <div class="chart-card" id="cardDaily">
        <h3>Daily Trend</h3>
        <canvas id="chartDaily"></canvas>
      </div>`);
    chartInstances.daily = new Chart(
      document.getElementById('chartDaily'), {
        type: 'bar',
        data: {
          labels: dayLabels,
          datasets: [
            { label: 'Entry',  data: dayLabels.map(d => days[d].ENTRY),  backgroundColor: 'rgba(22,163,74,0.65)' },
            { label: 'Exit',   data: dayLabels.map(d => days[d].EXIT),   backgroundColor: 'rgba(220,38,38,0.65)' },
            { label: 'Denied', data: dayLabels.map(d => days[d].DENIED), backgroundColor: 'rgba(217,119,6,0.65)' }
          ]
        },
        options: {
          plugins: { legend: { labels: { color: '#16233d', font: { family: 'Syne' } } } },
          scales: {
            x: { ticks: { color: '#8a9bb5' }, grid: { color: '#eef2f8' } },
            y: { ticks: { color: '#8a9bb5' }, grid: { color: '#eef2f8' }, beginAtZero: true }
          }
        }
      }
    );
  }

  // ---- PERCENTAGES TABLE ----
  const failedCard = document.getElementById('failedCard');
  failedCard.innerHTML = '';

  if (opt('optPct')) {
    const pctHtml = (count) => {
      const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
      return `${pct}% <span class="pct-bar-wrap"><span class="pct-bar" style="width:${pct}%;background:#1c3a5e"></span></span>`;
    };

    // By role breakdown
    const roles = {};
    data.forEach(r => { roles[r.role] = (roles[r.role] || 0) + 1; });

    grid.insertAdjacentHTML('beforeend', `
      <div class="chart-card" id="cardPct">
        <h3>Percentage Breakdown</h3>
        <table class="pct-table">
          <tr><th>Category</th><th>Count</th><th>% of Total</th></tr>
          <tr><td>Entry</td><td>${entries}</td><td>${pctHtml(entries)}</td></tr>
          <tr><td>Exit</td><td>${exits}</td><td>${pctHtml(exits)}</td></tr>
          <tr><td>Denied</td><td>${denied}</td><td>${pctHtml(denied)}</td></tr>
          ${Object.entries(roles).map(([role, count]) =>
            `<tr><td>${role}</td><td>${count}</td><td>${pctHtml(count)}</td></tr>`
          ).join('')}
        </table>
      </div>`);
  }

  // ---- FAILED ATTEMPTS ----
  if (opt('optFailed')) {
    const deniedLogs = data.filter(r => r.type === 'DENIED');

    // Group by name or id
    const failMap = {};
    deniedLogs.forEach(r => {
      const key = r.name || r.id_number || 'Unknown';
      if (!failMap[key]) failMap[key] = { count: 0, last: r.timestamp, role: r.role };
      failMap[key].count++;
      if (r.timestamp > failMap[key].last) failMap[key].last = r.timestamp;
    });

    const sorted = Object.entries(failMap).sort((a, b) => b[1].count - a[1].count);

    failedCard.innerHTML = `
      <h3>⚠ Failed / Denied Attempts (${deniedLogs.length} total)</h3>
      ${sorted.length === 0
        ? `<div style="color:#c9a45c;font-size:13px;">No denied attempts found.</div>`
        : `<div class="failed-list">
            ${sorted.map(([name, info]) => `
              <div class="failed-row">
                <div>
                  <div class="fname">${name}</div>
                  <div class="ftime">${info.role} · Last attempt: ${info.last}</div>
                </div>
                <span class="failed-count">${info.count}×</span>
              </div>
            `).join('')}
          </div>`
      }`;
  }
}

/* ===== EXPORT PDF ===== */
async function exportPDF() {
  const { jsPDF } = window.jspdf;
  const msg = document.getElementById('exportingMsg');
  msg.classList.add('show');

  await new Promise(r => setTimeout(r, 100)); // let UI update

  try {
    const pdf = new jsPDF('p', 'mm', 'a4');
    const pageW = pdf.internal.pageSize.getWidth();
    const pageH = pdf.internal.pageSize.getHeight();
    let y = 15;

    // ---- Header ----
    pdf.setFillColor(255, 255, 255);
    pdf.rect(0, 0, pageW, pageH, 'F');

    pdf.setTextColor(22, 35, 61);
    pdf.setFontSize(18);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Access Logs Report', 14, y);
    y += 7;

    pdf.setFontSize(9);
    pdf.setTextColor(140, 150, 170);
    pdf.text(`Generated: ${new Date().toLocaleString()}`, 14, y);
    y += 4;
    pdf.text(`Total records in view: ${filtered.length}`, 14, y);
    y += 10;

    // ---- Stats summary ----
    const entries = filtered.filter(r => r.type === 'ENTRY').length;
    const exits   = filtered.filter(r => r.type === 'EXIT').length;
    const denied  = filtered.filter(r => r.type === 'DENIED').length;

    const statBoxes = [
      { label: 'Total',   value: filtered.length, color: [28,58,94] },
      { label: 'Entries', value: entries,          color: [22,163,74] },
      { label: 'Exits',   value: exits,            color: [220,38,38] },
      { label: 'Denied',  value: denied,           color: [217,119,6] }
    ];

    const bw = (pageW - 28) / 4 - 3;
    statBoxes.forEach((s, i) => {
      const bx = 14 + i * (bw + 4);
      pdf.setFillColor(244, 247, 251);
      pdf.setDrawColor(220, 228, 239);
      pdf.roundedRect(bx, y, bw, 16, 3, 3, 'FD');
      pdf.setTextColor(...s.color);
      pdf.setFontSize(14);
      pdf.setFont('helvetica', 'bold');
      pdf.text(String(s.value), bx + bw / 2, y + 8, { align: 'center' });
      pdf.setFontSize(7);
      pdf.setTextColor(140,150,170);
      pdf.text(s.label.toUpperCase(), bx + bw / 2, y + 13, { align: 'center' });
    });
    y += 22;

    // ---- Charts (if report is open) ----
    if (reportOpen) {
      const chartIds = [
        { id: 'chartOverview', opt: 'optOverview', label: 'Overview' },
        { id: 'chartRole',     opt: 'optRole',     label: 'By Role' },
        { id: 'chartHourly',   opt: 'optHourly',   label: 'Hourly Activity' },
        { id: 'chartDaily',    opt: 'optDaily',     label: 'Daily Trend' },
      ];

      for (const c of chartIds) {
        if (!opt(c.opt)) continue;
        const canvas = document.getElementById(c.id);
        if (!canvas) continue;

        const imgData = canvas.toDataURL('image/png');
        const imgW = pageW - 28;
        const imgH = imgW * 0.45;

        if (y + imgH > pageH - 15) { pdf.addPage(); pdf.setFillColor(255,255,255); pdf.rect(0,0,pageW,pageH,'F'); y = 15; }

        pdf.setTextColor(70,85,110);
        pdf.setFontSize(9);
        pdf.setFont('helvetica', 'bold');
        pdf.text(c.label, 14, y);
        y += 4;
        pdf.addImage(imgData, 'PNG', 14, y, imgW, imgH);
        y += imgH + 10;
      }

      // ---- Pct table in PDF ----
      if (opt('optPct')) {
        if (y + 50 > pageH - 15) { pdf.addPage(); pdf.setFillColor(255,255,255); pdf.rect(0,0,pageW,pageH,'F'); y = 15; }

        pdf.setTextColor(70,85,110);
        pdf.setFontSize(9);
        pdf.setFont('helvetica', 'bold');
        pdf.text('Percentage Breakdown', 14, y);
        y += 6;

        const rows = [
          ['Entry',  entries, filtered.length],
          ['Exit',   exits,   filtered.length],
          ['Denied', denied,  filtered.length],
        ];

        const roles = {};
        filtered.forEach(r => { roles[r.role] = (roles[r.role] || 0) + 1; });
        Object.entries(roles).forEach(([role, count]) => rows.push([role, count, filtered.length]));

        rows.forEach(([label, count, tot]) => {
          const pct = tot > 0 ? ((count / tot) * 100).toFixed(1) : '0.0';
          pdf.setFontSize(8);
          pdf.setTextColor(90,100,120);
          pdf.setFont('helvetica', 'normal');
          pdf.text(label, 14, y);
          pdf.text(String(count), 70, y);
          pdf.text(`${pct}%`, 100, y);

          // bar
          pdf.setFillColor(230,235,242);
          pdf.roundedRect(120, y - 3, 60, 4, 1, 1, 'F');
          pdf.setFillColor(28,58,94);
          pdf.roundedRect(120, y - 3, Math.max(1, 60 * parseFloat(pct) / 100), 4, 1, 1, 'F');

          y += 7;
        });
        y += 6;
      }

      // ---- Failed attempts in PDF ----
      if (opt('optFailed')) {
        const deniedLogs = filtered.filter(r => r.type === 'DENIED');
        const failMap = {};
        deniedLogs.forEach(r => {
          const key = r.name || r.id_number || 'Unknown';
          if (!failMap[key]) failMap[key] = { count: 0, last: r.timestamp, role: r.role };
          failMap[key].count++;
          if (r.timestamp > failMap[key].last) failMap[key].last = r.timestamp;
        });
        const sorted = Object.entries(failMap).sort((a, b) => b[1].count - a[1].count);

        if (y + 20 > pageH - 15) { pdf.addPage(); pdf.setFillColor(255,255,255); pdf.rect(0,0,pageW,pageH,'F'); y = 15; }

        pdf.setTextColor(217,119,6);
        pdf.setFontSize(9);
        pdf.setFont('helvetica', 'bold');
        pdf.text(`Failed / Denied Attempts (${deniedLogs.length} total)`, 14, y);
        y += 7;

        if (sorted.length === 0) {
          pdf.setTextColor(140,150,170);
          pdf.setFontSize(8);
          pdf.text('No denied attempts found.', 14, y);
          y += 8;
        } else {
          sorted.forEach(([name, info]) => {
            if (y + 10 > pageH - 15) { pdf.addPage(); pdf.setFillColor(255,255,255); pdf.rect(0,0,pageW,pageH,'F'); y = 15; }
            pdf.setFillColor(255, 250, 235);
            pdf.setDrawColor(246, 226, 179);
            pdf.roundedRect(14, y - 4, pageW - 28, 9, 2, 2, 'FD');
            pdf.setTextColor(22,35,61);
            pdf.setFontSize(8);
            pdf.setFont('helvetica', 'bold');
            pdf.text(name, 18, y);
            pdf.setFont('helvetica', 'normal');
            pdf.setTextColor(140,150,170);
            pdf.text(`${info.role} · Last: ${info.last}`, 18, y + 4);
            pdf.setTextColor(217,119,6);
            pdf.setFont('helvetica', 'bold');
            pdf.text(`${info.count}×`, pageW - 20, y, { align: 'right' });
            y += 12;
          });
        }
        y += 4;
      }
    }

    // ---- Log table ----
    if (y + 20 > pageH - 15) { pdf.addPage(); pdf.setFillColor(255,255,255); pdf.rect(0,0,pageW,pageH,'F'); y = 15; }

    pdf.setTextColor(70,85,110);
    pdf.setFontSize(9);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Log Records', 14, y);
    y += 6;

    const cols = ['ID','Name','Role','Status','Type','Timestamp'];
    const colW  = [20, 42, 22, 22, 18, 44];
    let cx = 14;

    pdf.setFillColor(244,247,251);
    pdf.rect(14, y - 4, pageW - 28, 8, 'F');
    cols.forEach((col, i) => {
      pdf.setTextColor(140,150,170);
      pdf.setFontSize(7);
      pdf.text(col.toUpperCase(), cx, y);
      cx += colW[i];
    });
    y += 6;

    filtered.forEach((r, idx) => {
      if (y + 8 > pageH - 15) {
        pdf.addPage();
        pdf.setFillColor(255,255,255);
        pdf.rect(0,0,pageW,pageH,'F');
        y = 15;
      }
      if (idx % 2 === 0) {
        pdf.setFillColor(249,251,253);
        pdf.rect(14, y - 4, pageW - 28, 7, 'F');
      }
      cx = 14;
      const rowData = [
        r.id_number || '',
        r.name || '',
        r.role || '',
        r.status || '',
        r.type || '',
        r.timestamp || ''
      ];
      rowData.forEach((val, i) => {
        const color = i === 4 && r.type === 'ENTRY' ? [22,163,74]
                    : i === 4 && r.type === 'EXIT'  ? [220,38,38]
                    : i === 4 && r.type === 'DENIED' ? [217,119,6]
                    : [70,80,100];
        pdf.setTextColor(...color);
        pdf.setFontSize(7);
        pdf.setFont('helvetica', i === 1 ? 'bold' : 'normal');
        const text = String(val).substring(0, 30);
        pdf.text(text, cx, y);
        cx += colW[i];
      });
      y += 7;
    });

    pdf.save(`access_logs_${new Date().toISOString().slice(0,10)}.pdf`);

  } catch (err) {
    console.error(err);
    alert('PDF export failed: ' + err.message);
  }

  msg.classList.remove('show');
}

render();
</script>
</body>
</html>