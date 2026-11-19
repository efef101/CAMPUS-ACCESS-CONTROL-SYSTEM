<?php
session_start();
include 'db.php';
include_once 'auth.php';

// Admins and officers can view logs; anyone else is sent to the login page
require_auth($conn, ['admin', 'officer']);

// Logged-in username for the sidebar badge
$loggedName = '';
if (!empty($_SESSION['admin_username']))        { $loggedName = $_SESSION['admin_username']; }
elseif (!empty($_SESSION['officer_username']))  { $loggedName = $_SESSION['officer_username']; }
if ($loggedName === '') { $loggedName = !empty($_SESSION['admin_logged_in']) ? 'Admin' : (!empty($_SESSION['officer_logged_in']) ? 'Officer' : 'Staff'); }

// Logs now come from access_logs (aliased to the same field names the page uses)
$result = $conn->query("SELECT a.id, a.id_number, a.name_snapshot AS name, COALESCE(a.person_type,'') AS role, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, a.event AS type, a.reason, a.flagged, a.logged_at AS timestamp FROM access_logs a ORDER BY a.logged_at DESC, a.id DESC");

$logs = [];

while ($result && $row = $result->fetch_assoc()) {
  $logs[] = $row;
}

// JSON_HEX_* prevents log data from breaking the script block
$logsJson = json_encode(
  $logs,
  JSON_HEX_TAG |
  JSON_HEX_AMP |
  JSON_HEX_APOS |
  JSON_HEX_QUOT
);

// Inline SVG icons
function icon($name) {
  $paths = [
    'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'chart'  => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    'logout' => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    'live'   => '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/>',
  ];

  return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin - Access Logs</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>

<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--ink:#16233d;--navy:#1c3a5e;--line:#dce4ef;--muted:#8a9bb5;--gold:#f0b429;--gold-soft:#fffdf5;--gold-glow:0 8px 24px rgba(240,180,41,0.25);--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#fafbfd;min-height:100vh;display:flex;color:var(--ink)}
svg{fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}

.sidebar{width:220px;flex-shrink:0;background:linear-gradient(180deg,#1c3a5e,#0f2440);border-right:1px solid #0f2440;height:100vh;position:sticky;top:0;display:flex;flex-direction:column;align-items:stretch;padding:24px 18px;gap:12px}
.sidebar .logo { display: flex; flex-direction: column; align-items: center; gap: 10px; text-align: center; }
.sidebar .logo-text { display: flex; flex-direction: column; gap: 2px; }
.sidebar .logo-univ { font-size: 12px; font-weight: 700; line-height: 1.3; color: #fff; }
.sidebar .logo-campus { font-size: 11px; font-weight: 500; color: rgba(255,255,255,0.6); }
.sidebar .logo img { width: 44px; height: 44px; border-radius: 50%; object-fit: cover; }
.sidebar-divider{width:100%;height:1px;background:rgba(255,255,255,0.12);margin:4px 0}
.sidebar .nav-item{display:flex;align-items:center;gap:14px;width:100%;color:#fff;text-decoration:none;font-size:14px;font-weight:500;white-space:nowrap;position:relative}
.sidebar .nav-icon{width:44px;height:44px;border-radius:12px;flex-shrink:0;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);display:flex;align-items:center;justify-content:center;transition:background .2s,border-color .2s,transform .2s}
.sidebar .nav-icon svg{width:20px;height:20px}
.sidebar .nav-label{color:rgba(255,255,255,0.85);overflow:hidden;text-overflow:ellipsis}
.sidebar .nav-item:hover .nav-icon{background:rgba(240,180,41,0.18);border-color:var(--gold);transform:translateY(-1px)}
.sidebar .nav-item.active .nav-icon{background:rgba(240,180,41,0.25);border-color:var(--gold)}
.sidebar .nav-item.active .nav-label{color:#fff;font-weight:600}
.sidebar .nav-item:focus-visible{outline:2px solid var(--gold);outline-offset:2px;border-radius:12px}
.sidebar .user-divider { margin-top: auto; }
.sidebar-user { display: flex; align-items: center; gap: 12px; width: 100%; padding: 4px 0; }
.su-avatar { width: 40px; height: 40px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; background: rgba(169,196,232,0.15); border: 1px solid rgba(169,196,232,0.35); color: #a9c4e8; font-size: 15px; font-weight: 700; }
.su-text { display: flex; flex-direction: column; min-width: 0; }
.su-name { font-size: 13px; font-weight: 600; color: #a9c4e8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.su-label { font-size: 10px; font-style: italic; color: rgba(169,196,232,0.6); margin-top: 1px; }
.sidebar .logout-item { margin-top: 0; }

.main{flex:1;min-width:0;padding:32px}
.header{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.header-left h1{font-size:22px;font-weight:600}
.header-left p{font-size:13px;color:var(--muted);margin-top:4px}
.header-right{display:flex;align-items:center;gap:10px}
.realtime-status{display:flex;align-items:center;gap:5px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:5px 9px;font-size:11px;color:#16a34a;font-weight:600}
.live-dot{width:6px;height:6px;border-radius:50%;background:#16a34a;box-shadow:0 0 0 3px rgba(22,163,74,0.12)}
.realtime-status.offline{color:#dc2626}
.realtime-status.offline .live-dot{background:#dc2626;box-shadow:0 0 0 3px rgba(220,38,38,0.12)}
.realtime-status.syncing{color:#d97706}
.realtime-status.syncing .live-dot{background:#d97706;box-shadow:0 0 0 3px rgba(217,119,6,0.12)}
.new-activity{display:none;margin-bottom:16px;padding:10px 13px;border-radius:10px;border:1px solid #ccebd9;background:#effaf3;color:#15803d;font-size:13px;font-weight:600}
.new-activity.show{display:flex;align-items:center;gap:8px}
.new-activity.alert{border-color:#f3b4b4;background:#fdeaea;color:#b91c1c}
.new-activity svg{width:16px;height:16px;flex-shrink:0}
.btn{display:inline-block;text-decoration:none;padding:11px 20px;border-radius:12px;border:1px solid var(--line);background:#fff;color:var(--ink);font-size:13px;font-weight:600;font-family:inherit;cursor:pointer;transition:transform .15s,background .15s,border-color .15s,box-shadow .15s}
.btn:hover{transform:translateY(-2px);background:var(--gold-soft);border-color:var(--gold);box-shadow:var(--gold-glow)}
.btn:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
.filters{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px}
.filters input,.filters select{background:#fff;border:1px solid var(--line);border-radius:10px;color:var(--ink);font-family:inherit;font-size:13px;padding:9px 14px;outline:none;transition:border-color .2s,box-shadow .2s;flex:1;min-width:140px}
.filters input::placeholder{color:#9aa9c2}
.filters input:focus,.filters select:focus{border-color:var(--gold);box-shadow:var(--gold-glow)}
.filters .btn{padding:9px 16px;font-weight:500;color:#6b7a94;white-space:nowrap;flex:0 0 auto;min-width:0}
.stats{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:#fff;border:1px solid var(--line);border-radius:14px;padding:16px 18px;flex:1;min-width:100px;text-align:center;box-shadow:0 1px 3px rgba(22,58,94,0.05);transition:border-color .2s,box-shadow .2s}
.stat:hover{border-color:var(--gold);box-shadow:var(--gold-glow)}
.stat-num{font-family:var(--mono);font-size:26px;font-weight:700}
.stat-label{font-size:11px;color:var(--muted);margin-top:2px;letter-spacing:0.08em;text-transform:uppercase}
.stat-num.entries{color:#16a34a}.stat-num.exits{color:#dc2626}.stat-num.total{color:var(--navy)}.stat-num.denied{color:#d97706}.stat-num.flagged{color:#b91c1c}
.report-bar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.report-bar .btn.active{background:var(--gold-soft);border-color:var(--gold)}
.export-btn{margin-left:auto;background:#e8f8ef;border-color:#b8ebc9;color:#16a34a}
.export-btn:hover{background:#d7f4e3}
#reportPanel{display:none;margin-bottom:24px}
#reportPanel.open{display:block}
.report-options{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;padding:16px;background:#fff;border:1px solid var(--line);border-radius:14px}
.report-options label{display:flex;align-items:center;gap:7px;font-size:13px;color:#4a5b78;cursor:pointer;padding:6px 12px;border-radius:8px;border:1px solid var(--line);transition:background .2s,border-color .2s}
.report-options label:hover{background:var(--gold-soft);border-color:var(--gold)}
.report-options input[type="checkbox"]{accent-color:var(--navy);width:14px;height:14px}
.report-options input[type="checkbox"]:checked + span{color:var(--navy)}
.chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:16px}
.chart-card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px;box-shadow:0 1px 3px rgba(22,58,94,0.05);transition:border-color .2s,box-shadow .2s}
.chart-card:hover{border-color:var(--gold);box-shadow:var(--gold-glow)}
.chart-card h3{font-size:12px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;color:var(--muted);margin-bottom:16px}
.chart-card canvas{max-height:220px}
.pct-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
.pct-table th{text-align:left;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#96a6c0;padding:6px 10px;font-weight:600;background:none;border:0;cursor:default}
.pct-table td{padding:7px 10px;font-family:var(--mono);font-size:12px;color:#3c4a63;border-top:1px solid #eef2f8}
.pct-bar-wrap{background:#eef2f8;border-radius:4px;height:6px;width:100px;overflow:hidden;display:inline-block;vertical-align:middle;margin-left:8px}
.pct-bar{height:100%;border-radius:4px;display:block}
.failed-card{background:#fffaf0;border:1px solid #f6e2b3;border-radius:14px;padding:20px;margin-bottom:16px}
.failed-card:empty{display:none}
.failed-card h3{font-size:12px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;color:#d97706;margin-bottom:14px}
.failed-list{display:flex;flex-direction:column;gap:8px;max-height:200px;overflow-y:auto}
.failed-row{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:#fff3da;border-radius:8px;font-size:12px}
.failed-row .fname{font-size:13px;color:var(--ink);font-weight:600}
.failed-row .ftime{color:#9aa9c2;font-size:11px;font-family:var(--mono)}
.failed-count{background:#fbe6b8;border:1px solid #f0cd82;color:#b4650a;border-radius:6px;padding:2px 8px;font-size:12px;font-weight:600}
.table-wrap{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 1px 3px rgba(22,58,94,0.05)}
.table-scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
thead tr{background:#f4f7fb}
th{padding:14px 16px;text-align:left;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#96a6c0;font-weight:600;cursor:pointer;user-select:none;white-space:nowrap;transition:color .2s}
th:hover{color:var(--ink)}
th .sort-icon{margin-left:4px;opacity:0.4}
tbody tr{border-top:1px solid #eef2f8;transition:background .15s}
tbody tr:hover{background:#f7fafd}
tbody tr.flagged-row{background:#fff5f5}
td{padding:12px 16px;color:#3c4a63;font-family:var(--mono);font-size:12px}
td.name-col{font-family:inherit;font-size:13px;font-weight:600;color:var(--ink)}
td.reason-text{font-family:inherit;font-size:12px;color:#6b7a94}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:0.05em;font-family:inherit}
.badge.entry{background:#e8f8ef;color:#16a34a;border:1px solid #bdeccf}
.badge.exit{background:#fdeaea;color:#dc2626;border:1px solid #f6c6c6}
.badge.denied{background:#dc2626;color:#fff;border:1px solid #dc2626}
.flag-mark{margin-left:6px;font-size:11px;font-weight:700;color:#b91c1c;font-family:inherit;white-space:nowrap}
.role-badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;background:#eef3fa;color:var(--navy);border:1px solid #c7d7ec;font-family:inherit}
.no-results{padding:40px;text-align:center;color:#b7c3d6;font-size:14px;font-family:inherit}
.pagination{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-top:1px solid #eef2f8;font-size:12px;color:var(--muted);flex-wrap:wrap;gap:10px}
.page-btns{display:flex;gap:6px;flex-wrap:wrap}
.page-btns button{background:#f4f7fb;border:1px solid var(--line);border-radius:8px;color:#6b7a94;font-size:12px;padding:5px 12px;cursor:pointer;font-family:inherit;transition:background .15s,border-color .15s}
.page-btns button:hover:not(:disabled){background:var(--gold-soft);border-color:var(--gold);color:var(--ink)}
.page-btns button:disabled{opacity:0.4;cursor:default}
.page-btns button.active{background:var(--gold-soft);border-color:var(--gold);color:var(--navy);font-weight:600}
#exportingMsg{display:none;position:fixed;inset:0;background:rgba(22,35,61,0.55);backdrop-filter:blur(6px);z-index:9999;justify-content:center;align-items:center;flex-direction:column;gap:12px;font-size:14px;color:#fff}
#exportingMsg.show{display:flex}
.spinner{width:32px;height:32px;border:3px solid rgba(255,255,255,0.2);border-top-color:#fff;border-radius:50%;animation:spin 0.8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

@media (max-width:860px){
  .sidebar{width:64px;padding:24px 10px}
  .sidebar .nav-label{display:none}
  .sidebar .logo-text { display: none; }
  .su-text { display: none; }
  .sidebar-user { justify-content: center; }
  .sidebar .logo img{width:40px;height:40px}
  .nav-item::after{content:attr(data-tip);position:absolute;left:54px;background:var(--ink);color:#fff;font-size:11px;padding:4px 10px;border-radius:6px;white-space:nowrap;border:1px solid rgba(255,255,255,0.1);opacity:0;pointer-events:none;transition:opacity .15s;z-index:100}
  .nav-item:hover::after,.nav-item:focus-visible::after{opacity:1}
  .main{padding:20px}

}
@media (prefers-reduced-motion:reduce){.btn,.sidebar .nav-icon,.report-bar button,.filters button{transition:none}.spinner{animation-duration:2s}}

</style>
</head>

<body>

<nav class="sidebar" aria-label="Main">
  <div class="logo">
    <img src="lego.png" alt="Lego">
    <div class="logo-text">
      <span class="logo-univ">Cebu Technological University</span>
      <span class="logo-campus">Main Campus</span>
    </div>
  </div>
  <div class="sidebar-divider"></div>
    <a class="nav-item" href="admin_dashboard.php" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="users.php" data-tip="Users" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item" href="manage_security.php" data-tip="Security Accounts" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
  <a class="nav-item active" aria-current="page" href="admin_logs.php" data-tip="Access Logs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item" href="security_summary.php?from=admin" data-tip="Security Overview" aria-label="Security Overview"><span class="nav-icon"><?= icon('chart') ?></span><span class="nav-label">Security Overview</span></a>
  <a class="nav-item" href="authentication_logs.php?from=admin" data-tip="Activity Logs" aria-label="Activity Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Activity Logs</span></a>
  <div class="sidebar-divider user-divider"></div>
  <div class="sidebar-user" title="<?= htmlspecialchars($loggedName) ?>">
    <span class="su-avatar"><?= htmlspecialchars(strtoupper(substr($loggedName, 0, 1))) ?></span>
    <span class="su-text">
      <span class="su-name"><?= htmlspecialchars($loggedName) ?></span>
      <span class="su-label">Logged in</span>
    </span>
  </div>
  <a class="nav-item logout-item" href="admin_logout.php" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<main class="main">

  <div id="exportingMsg"><div class="spinner"></div><span>Generating PDF...</span></div>

  <div class="header">
    <div class="header-left">
      <h1>Access Logs</h1>
      <p>Search, filter, report on and export campus entry activity.</p>
    </div>
    <div class="header-right">
      <div class="realtime-status" id="realtimeStatus" title="Monitoring connection">
        <span class="live-dot"></span><span id="realtimeText">LIVE</span>
      </div>
      <a href="admin_dashboard.php" class="btn">Back to Dashboard</a>
    </div>
  </div>

  <div class="new-activity" id="newActivity">
    <?= icon('live') ?>
    <span id="newActivityText">New access activity detected.</span>
  </div>

  <div class="filters">
    <input type="text" id="searchName" placeholder="Search name or ID..." oninput="applyFilters()">
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
      <option value="FLAGGED">Flagged only</option>
    </select>
    <input type="date" id="filterDate" onchange="applyFilters()">
    <button class="btn" onclick="clearFilters()">✕ Clear</button>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-num total" id="statTotal">0</div><div class="stat-label">Total</div></div>
    <div class="stat"><div class="stat-num entries" id="statEntries">0</div><div class="stat-label">Entries</div></div>
    <div class="stat"><div class="stat-num exits" id="statExits">0</div><div class="stat-label">Exits</div></div>
    <div class="stat"><div class="stat-num denied" id="statDenied">0</div><div class="stat-label">Denied</div></div>
    <div class="stat"><div class="stat-num flagged" id="statFlagged">0</div><div class="stat-label">Flagged</div></div>
  </div>

  <div class="report-bar">
    <button class="btn" id="reportToggleBtn" onclick="toggleReport()"><span id="reportToggleLabel">Generate Report</span></button>
    <button class="btn export-btn" onclick="exportPDF()">⬇ Export PDF</button>
  </div>

  <div id="reportPanel">
    <div class="report-options">
      <label><input type="checkbox" id="optOverview" checked onchange="buildCharts()"><span>Overview Chart</span></label>
      <label><input type="checkbox" id="optRole" checked onchange="buildCharts()"><span>By Role</span></label>
      <label><input type="checkbox" id="optHourly" checked onchange="buildCharts()"><span>Hourly Activity</span></label>
      <label><input type="checkbox" id="optDaily" checked onchange="buildCharts()"><span>Daily Trend</span></label>
      <label><input type="checkbox" id="optPct" checked onchange="buildCharts()"><span>Percentages</span></label>
      <label><input type="checkbox" id="optFailed" checked onchange="buildCharts()"><span>Failed Attempts</span></label>
    </div>
    <div class="chart-grid" id="chartGrid"></div>
    <div class="failed-card" id="failedCard"></div>
  </div>

  <div class="table-wrap" id="logTableWrap">
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th onclick="sortBy('id_number')">ID <span class="sort-icon">↕</span></th>
            <th onclick="sortBy('name')">Name <span class="sort-icon">↕</span></th>
            <th onclick="sortBy('role')">Role <span class="sort-icon">↕</span></th>
            <th onclick="sortBy('status')">Status <span class="sort-icon">↕</span></th>
            <th onclick="sortBy('type')">Type <span class="sort-icon">↕</span></th>
            <th onclick="sortBy('reason')">Reason <span class="sort-icon">↕</span></th>
            <th onclick="sortBy('timestamp')">Time <span class="sort-icon">↕</span></th>
          </tr>
        </thead>
        <tbody id="logsBody"></tbody>
      </table>
    </div>
    <div class="pagination">
      <span id="pageInfo">Showing 0 results</span>
      <div class="page-btns" id="pageBtns"></div>
    </div>
  </div>

</main>

<script>
/* ===== DATA ===== */
let allLogs = <?= $logsJson ?>;
let filtered = [...allLogs];
let sortKey = 'timestamp', sortDir = -1, page = 1;
let chartInstances = {}, reportOpen = false;
const perPage = 10;
const FONT = { family: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' };
const REASONS = { UNKNOWN_ID: 'ID not found', QR_EXPIRED: 'QR expired', FACE_MISMATCH: 'Face mismatch', NOT_REGISTERED: 'Not registered' };
const reasonLabel = r => r ? (REASONS[r] || r) : '';
const isFlagged = r => Number(r.flagged) === 1;


function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const $ = id => document.getElementById(id);
const opt = id => $(id).checked;

/* ===== FILTERS ===== */
function applyFilters() {
  const name = $('searchName').value.toLowerCase().trim();
  const role = $('filterRole').value.toLowerCase();
  const type = $('filterType').value.toUpperCase();
  const date = $('filterDate').value;

  filtered = allLogs.filter(r => {
    const okName = !name || (r.name || '').toLowerCase().includes(name) || String(r.id_number || '').toLowerCase().includes(name);
    const okRole = !role || (r.role || '').toLowerCase() === role;
    const okType = !type || (type === 'FLAGGED' ? isFlagged(r) : (r.type || '').toUpperCase() === type);
    const okDate = !date || (r.timestamp || '').startsWith(date);
    return okName && okRole && okType && okDate;
  });

  page = 1;
  render();
  if (reportOpen) buildCharts();
}

function clearFilters() {
  ['searchName', 'filterRole', 'filterType', 'filterDate'].forEach(id => $(id).value = '');
  filtered = [...allLogs];
  page = 1;
  render();
  if (reportOpen) buildCharts();
}

function sortBy(key) {
  if (sortKey === key) { sortDir *= -1; } else { sortKey = key; sortDir = -1; }
  filtered.sort((a, b) => {
    const av = a[key] ?? '', bv = b[key] ?? '';
    return av > bv ? sortDir : av < bv ? -sortDir : 0;
  });
  render();
}

/* ===== TABLE ===== */
function render() {
  const start = (page - 1) * perPage;
  const rows = filtered.slice(start, start + perPage);
  const count = t => filtered.filter(r => r.type === t).length;

  $('statTotal').textContent   = filtered.length;
  $('statEntries').textContent = count('ENTRY');
  $('statExits').textContent   = count('EXIT');
  $('statDenied').textContent  = count('DENIED');
  $('statFlagged').textContent = filtered.filter(isFlagged).length;

  $('logsBody').innerHTML = rows.length === 0
    ? '<tr><td colspan="7"><div class="no-results">No logs found</div></td></tr>'
    : rows.map(r => {
        const cls = r.type === 'ENTRY' ? 'entry' : r.type === 'EXIT' ? 'exit' : 'denied';
        return `<tr${isFlagged(r) ? ' class="flagged-row"' : ''}>
          <td>${esc(r.id_number)}</td>
          <td class="name-col">${esc(r.name)}</td>
          <td><span class="role-badge">${esc(r.role)}</span></td>
          <td>${esc(r.status)}</td>
          <td><span class="badge ${cls}">${esc(r.type)}</span>${isFlagged(r) ? '<span class="flag-mark">⚑ FLAGGED</span>' : ''}</td>
          <td class="reason-text">${esc(reasonLabel(r.reason))}</td>
          <td>${esc(r.timestamp)}</td>
        </tr>`;
      }).join('');

  const totalPages = Math.ceil(filtered.length / perPage);
  $('pageInfo').textContent = `Showing ${filtered.length === 0 ? 0 : start + 1}–${Math.min(start + perPage, filtered.length)} of ${filtered.length}`;

  let btns = `<button type="button" onclick="goPage(${page - 1})" ${page === 1 ? 'disabled' : ''}>‹ Prev</button>`;
  for (let i = 1; i <= totalPages; i++) {
    btns += `<button type="button" class="${i === page ? 'active' : ''}" onclick="goPage(${i})">${i}</button>`;
  }
  btns += `<button type="button" onclick="goPage(${page + 1})" ${page === totalPages || totalPages === 0 ? 'disabled' : ''}>Next ›</button>`;
  $('pageBtns').innerHTML = btns;
}

function goPage(p) {
  const totalPages = Math.ceil(filtered.length / perPage);
  if (p < 1 || p > totalPages) return;
  page = p;
  render();
}

/* ===== REPORT ===== */
function toggleReport() {
  reportOpen = !reportOpen;
  $('reportPanel').classList.toggle('open', reportOpen);
  $('reportToggleBtn').classList.toggle('active', reportOpen);
  $('reportToggleLabel').textContent = reportOpen ? 'Close Report' : 'Generate Report';
  if (reportOpen) buildCharts();
}

const LINES = [['Entry', 'ENTRY', '#16a34a', '22,163,74'], ['Exit', 'EXIT', '#dc2626', '220,38,38'], ['Denied', 'DENIED', '#d97706', '217,119,6']];

function failedMap(list) {
  const map = {};
  list.forEach(r => {
    const key = r.name || r.id_number || 'Unknown';
    if (!map[key]) map[key] = { count: 0, last: r.timestamp, role: r.role };
    map[key].count++;
    if (r.timestamp > map[key].last) map[key].last = r.timestamp;
  });
  return Object.entries(map).sort((a, b) => b[1].count - a[1].count);
}

function buildCharts() {
  const data = filtered, total = data.length;
  const count = t => data.filter(r => r.type === t).length;
  const entries = count('ENTRY'), exits = count('EXIT'), denied = count('DENIED');
  const grid = $('chartGrid');
  grid.innerHTML = '';
  Object.values(chartInstances).forEach(c => { try { c.destroy(); } catch (e) {} });
  chartInstances = {};

  const legend = { labels: { color: '#16233d', font: FONT } };
  const scales = (color, xExtra = {}) => ({
    x: { ticks: { color, ...xExtra }, grid: { color: '#eef2f8' } },
    y: { ticks: { color }, grid: { color: '#eef2f8' }, beginAtZero: true }
  });
  const tally = keyFn => {
    const m = {};
    data.forEach(r => {
      const k = keyFn(r);
      if (k === null) return;
      if (!m[k]) m[k] = { ENTRY: 0, EXIT: 0, DENIED: 0 };
      m[k][r.type] = (m[k][r.type] || 0) + 1;
    });
    return m;
  };
  const bars  = (labels, m) => LINES.map(([n, k, , rgb]) => ({ label: n, data: labels.map(l => m[l][k]), backgroundColor: `rgba(${rgb},0.65)` }));
  const lines = (labels, m) => LINES.map(([n, k, c, rgb]) => ({ label: n, data: labels.map(l => m[l][k]), borderColor: c, backgroundColor: `rgba(${rgb},0.08)`, tension: 0.4, fill: true }));
  const card  = (id, title, config) => {
    grid.insertAdjacentHTML('beforeend', `<div class="chart-card"><h3>${title}</h3><canvas id="${id}"></canvas></div>`);
    chartInstances[id] = new Chart($(id), config);
  };

  if (opt('optOverview')) {
    card('chartOverview', 'Overview — Entry / Exit / Denied', {
      type: 'doughnut',
      data: { labels: ['Entry', 'Exit', 'Denied'], datasets: [{ data: [entries, exits, denied], backgroundColor: ['rgba(22,163,74,0.75)', 'rgba(220,38,38,0.75)', 'rgba(217,119,6,0.75)'], borderWidth: 0 }] },
      options: { plugins: { legend } }
    });
  }

  if (opt('optRole')) {
    const m = tally(r => r.role || 'unknown'), labels = Object.keys(m);
    card('chartRole', 'Activity by Role', { type: 'bar', data: { labels, datasets: bars(labels, m) }, options: { plugins: { legend }, scales: scales('#6b7a94') } });
  }

  if (opt('optHourly')) {
    const m = {};
    for (let h = 0; h < 24; h++) m[h] = { ENTRY: 0, EXIT: 0, DENIED: 0 };
    data.forEach(r => {
      const h = new Date(String(r.timestamp).replace(' ', 'T')).getHours();
      if (!isNaN(h)) m[h][r.type] = (m[h][r.type] || 0) + 1;
    });
    const keys = Object.keys(m);
    card('chartHourly', 'Hourly Activity', {
      type: 'line',
      data: { labels: keys.map(h => String(h).padStart(2, '0') + ':00'), datasets: lines(keys, m) },
      options: { plugins: { legend }, scales: scales('#8a9bb5', { maxTicksLimit: 12 }) }
    });
  }

  if (opt('optDaily')) {
    const m = tally(r => (r.timestamp || '').slice(0, 10) || null), labels = Object.keys(m).sort();
    card('chartDaily', 'Daily Trend', { type: 'bar', data: { labels, datasets: bars(labels, m) }, options: { plugins: { legend }, scales: scales('#8a9bb5') } });
  }

  const failedCard = $('failedCard');
  failedCard.innerHTML = '';

  if (opt('optPct')) {
    const pctHtml = n => {
      const pct = total > 0 ? ((n / total) * 100).toFixed(1) : '0.0';
      return `${pct}% <span class="pct-bar-wrap"><span class="pct-bar" style="width:${pct}%;background:#1c3a5e"></span></span>`;
    };
    const roles = {};
    data.forEach(r => { roles[r.role] = (roles[r.role] || 0) + 1; });
    const flaggedCount = data.filter(isFlagged).length;
    grid.insertAdjacentHTML('beforeend', `<div class="chart-card"><h3>Percentage Breakdown</h3>
      <table class="pct-table">
        <tr><th>Category</th><th>Count</th><th>% of Total</th></tr>
        <tr><td>Entry</td><td>${entries}</td><td>${pctHtml(entries)}</td></tr>
        <tr><td>Exit</td><td>${exits}</td><td>${pctHtml(exits)}</td></tr>
        <tr><td>Denied</td><td>${denied}</td><td>${pctHtml(denied)}</td></tr>
        <tr><td>Flagged</td><td>${flaggedCount}</td><td>${pctHtml(flaggedCount)}</td></tr>
        ${Object.entries(roles).map(([role, n]) => `<tr><td>${esc(role)}</td><td>${n}</td><td>${pctHtml(n)}</td></tr>`).join('')}
      </table></div>`);
  }

  if (opt('optFailed')) {
    const deniedLogs = data.filter(r => r.type === 'DENIED');
    const sorted = failedMap(deniedLogs);
    failedCard.innerHTML = `<h3>⚠ Failed / Denied Attempts (${deniedLogs.length} total)</h3>` + (sorted.length === 0
      ? '<div style="color:#c9a45c;font-size:13px">No denied attempts found.</div>'
      : `<div class="failed-list">${sorted.map(([name, info]) => `
          <div class="failed-row">
            <div><div class="fname">${esc(name)}</div><div class="ftime">${esc(info.role)} · Last attempt: ${esc(info.last)}</div></div>
            <span class="failed-count">${info.count}×</span>
          </div>`).join('')}</div>`);
  }
}

/* ===== REAL-TIME ===== */
let realtimeTimer = null, realtimeBusy = false;

function setRealtimeStatus(state, text) {
  const box = $('realtimeStatus');
  if (!box) return;
  box.classList.remove('offline', 'syncing');
  if (state === 'offline') box.classList.add('offline');
  if (state === 'syncing') box.classList.add('syncing');
  $('realtimeText').textContent = text;
}

function showNewActivity(newLogs) {
  const box = $('newActivity'), text = $('newActivityText');
  if (!box || !text || !newLogs.length) return;
  const flagged = newLogs.find(isFlagged);
  const latest = newLogs[0];
  if (flagged) {
    text.textContent = `⚑ Suspicious activity flagged: ${flagged.name || flagged.id_number || 'Unknown'}.`;
  } else if (newLogs.length === 1) {
    text.textContent = `New access activity: ${latest.name || latest.id_number || 'Unknown'} — ${latest.type || 'ACCESS'}.`;
  } else {
    text.textContent = `${newLogs.length} new access activities detected.`;
  }
  box.classList.toggle('alert', !!flagged);
  box.classList.add('show');
  clearTimeout(window.newActivityTimeout);
  window.newActivityTimeout = setTimeout(() => box.classList.remove('show'), 5000);
}

let latestLogId = allLogs.reduce((max, log) => Math.max(max, Number(log.id) || 0), 0);

async function checkRealtimeLogs() {
  if (realtimeBusy) return;
  realtimeBusy = true;
  setRealtimeStatus('syncing', 'SYNCING');

  try {
    const url = new URL('realtime_logs.php', window.location.href);
    url.searchParams.set('since_id', latestLogId);
    url.searchParams.set('_', Date.now());

    const response = await fetch(url.toString(), {
      method: 'GET', cache: 'no-store', credentials: 'same-origin',
      headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' }
    });
    if (!response.ok) throw new Error(`Realtime request failed: HTTP ${response.status}`);

    const data = await response.json();
    if (!data || data.success !== true || !Array.isArray(data.logs)) {
      throw new Error((data && data.message) || 'Invalid realtime response');
    }

    const existing = new Set(allLogs.map(l => String(l.id)));
    const fresh = data.logs.filter(l => (Number(l.id) || 0) > latestLogId && !existing.has(String(l.id)));

    if (fresh.length > 0) {
      allLogs = [...fresh, ...allLogs];
      latestLogId = Math.max(latestLogId, ...fresh.map(l => Number(l.id) || 0));
      allLogs.sort((a, b) => {
        const ia = Number(a.id) || 0, ib = Number(b.id) || 0;
        if (ia && ib) return ib - ia;
        return String(b.timestamp || '').localeCompare(String(a.timestamp || ''));
      });
      applyFilters();
      showNewActivity(fresh);
    }
    setRealtimeStatus('online', 'LIVE');
  } catch (error) {
    console.error('Realtime monitoring error:', error);
    setRealtimeStatus('offline', 'OFFLINE');
  } finally {
    realtimeBusy = false;
  }
}


function startRealtimeMonitoring() {
  checkRealtimeLogs();
  realtimeTimer = setInterval(checkRealtimeLogs, 3000);
}
window.addEventListener('beforeunload', () => { if (realtimeTimer) clearInterval(realtimeTimer); });

/* ===== EXPORT PDF ===== */
async function exportPDF() {
  const { jsPDF } = window.jspdf;
  const msg = $('exportingMsg');
  msg.classList.add('show');
  await new Promise(r => setTimeout(r, 100));

  try {
    const pdf = new jsPDF('p', 'mm', 'a4');
    const W = pdf.internal.pageSize.getWidth(), H = pdf.internal.pageSize.getHeight();
    let y = 15;
    const white = () => { pdf.setFillColor(255, 255, 255); pdf.rect(0, 0, W, H, 'F'); };
    const ensure = h => { if (y + h > H - 15) { pdf.addPage(); white(); y = 15; } };
    const font = (size, style, color) => { pdf.setFontSize(size); pdf.setFont('helvetica', style); pdf.setTextColor(...color); };

    const entries = filtered.filter(r => r.type === 'ENTRY').length;
    const exits   = filtered.filter(r => r.type === 'EXIT').length;
    const denied  = filtered.filter(r => r.type === 'DENIED').length;
    const flaggedN = filtered.filter(isFlagged).length;

    white();
    font(18, 'bold', [22, 35, 61]);
    pdf.text('Access Logs Report', 14, y); y += 7;
    font(9, 'normal', [140, 150, 170]);
    pdf.text(`Generated: ${new Date().toLocaleString()}`, 14, y); y += 4;
    pdf.text(`Total records in view: ${filtered.length}`, 14, y); y += 10;

    const boxes = [
      ['Total', filtered.length, [28, 58, 94]], ['Entries', entries, [22, 163, 74]], ['Exits', exits, [220, 38, 38]],
      ['Denied', denied, [217, 119, 6]], ['Flagged', flaggedN, [185, 28, 28]]
    ];
    const bw = (W - 28) / boxes.length - 3;
    boxes.forEach(([label, value, color], i) => {
      const bx = 14 + i * (bw + 3.5);
      pdf.setFillColor(244, 247, 251); pdf.setDrawColor(220, 228, 239);
      pdf.roundedRect(bx, y, bw, 16, 3, 3, 'FD');
      font(14, 'bold', color);
      pdf.text(String(value), bx + bw / 2, y + 8, { align: 'center' });
      font(7, 'normal', [140, 150, 170]);
      pdf.text(label.toUpperCase(), bx + bw / 2, y + 13, { align: 'center' });
    });
    y += 22;

    if (reportOpen) {
      const charts = [['chartOverview', 'optOverview', 'Overview'], ['chartRole', 'optRole', 'By Role'], ['chartHourly', 'optHourly', 'Hourly Activity'], ['chartDaily', 'optDaily', 'Daily Trend']];
      for (const [id, optId, label] of charts) {
        if (!opt(optId)) continue;
        const canvas = $(id);
        if (!canvas) continue;
        const imgW = W - 28, imgH = imgW * 0.45;
        ensure(imgH);
        font(9, 'bold', [70, 85, 110]);
        pdf.text(label, 14, y); y += 4;
        pdf.addImage(canvas.toDataURL('image/png'), 'PNG', 14, y, imgW, imgH);
        y += imgH + 10;
      }

      if (opt('optPct')) {
        ensure(50);
        font(9, 'bold', [70, 85, 110]);
        pdf.text('Percentage Breakdown', 14, y); y += 6;
        const rows = [['Entry', entries], ['Exit', exits], ['Denied', denied], ['Flagged', flaggedN]];
        const roles = {};
        filtered.forEach(r => { roles[r.role] = (roles[r.role] || 0) + 1; });
        Object.entries(roles).forEach(([role, n]) => rows.push([role, n]));
        rows.forEach(([label, n]) => {
          const pct = filtered.length > 0 ? ((n / filtered.length) * 100).toFixed(1) : '0.0';
          ensure(7);
          font(8, 'normal', [90, 100, 120]);
          pdf.text(String(label), 14, y); pdf.text(String(n), 70, y); pdf.text(`${pct}%`, 100, y);
          pdf.setFillColor(230, 235, 242); pdf.roundedRect(120, y - 3, 60, 4, 1, 1, 'F');
          pdf.setFillColor(28, 58, 94);    pdf.roundedRect(120, y - 3, Math.max(1, 60 * parseFloat(pct) / 100), 4, 1, 1, 'F');
          y += 7;
        });
        y += 6;
      }

      if (opt('optFailed')) {
        const deniedLogs = filtered.filter(r => r.type === 'DENIED');
        const sorted = failedMap(deniedLogs);
        ensure(20);
        font(9, 'bold', [217, 119, 6]);
        pdf.text(`Failed / Denied Attempts (${deniedLogs.length} total)`, 14, y); y += 7;
        if (sorted.length === 0) {
          font(8, 'normal', [140, 150, 170]);
          pdf.text('No denied attempts found.', 14, y); y += 8;
        } else {
          sorted.forEach(([name, info]) => {
            ensure(10);
            pdf.setFillColor(255, 250, 235); pdf.setDrawColor(246, 226, 179);
            pdf.roundedRect(14, y - 4, W - 28, 9, 2, 2, 'FD');
            font(8, 'bold', [22, 35, 61]);
            pdf.text(String(name), 18, y);
            font(8, 'normal', [140, 150, 170]);
            pdf.text(`${info.role} · Last: ${info.last}`, 18, y + 4);
            font(8, 'bold', [217, 119, 6]);
            pdf.text(`${info.count}×`, W - 20, y, { align: 'right' });
            y += 12;
          });
        }
        y += 4;
      }
    }

    ensure(20);
    font(9, 'bold', [70, 85, 110]);
    pdf.text('Log Records', 14, y); y += 6;

    const cols = ['ID', 'Name', 'Role', 'Status', 'Type', 'Reason', 'Timestamp'];
    const colW = [18, 36, 18, 16, 16, 36, 40];
    let cx = 14;
    pdf.setFillColor(244, 247, 251);
    pdf.rect(14, y - 4, W - 28, 8, 'F');
    cols.forEach((col, i) => { font(7, 'normal', [140, 150, 170]); pdf.text(col.toUpperCase(), cx, y); cx += colW[i]; });
    y += 6;

    filtered.forEach((r, idx) => {
      ensure(8);
      if (idx % 2 === 0) { pdf.setFillColor(249, 251, 253); pdf.rect(14, y - 4, W - 28, 7, 'F'); }
      cx = 14;
      const reason = reasonLabel(r.reason) + (isFlagged(r) ? ' [FLAGGED]' : '');
      [r.id_number || '', r.name || '', r.role || '', r.status || '', r.type || '', reason, r.timestamp || ''].forEach((val, i) => {
        const color = i === 4 && r.type === 'ENTRY' ? [22, 163, 74]
                    : i === 4 && r.type === 'EXIT' ? [220, 38, 38]
                    : i === 4 && r.type === 'DENIED' ? [217, 119, 6]
                    : i === 5 && isFlagged(r) ? [185, 28, 28]
                    : [70, 80, 100];
        font(7, i === 1 ? 'bold' : 'normal', color);
        pdf.text(String(val).substring(0, 30), cx, y);
        cx += colW[i];
      });
      y += 7;
    });

    pdf.save(`access_logs_${new Date().toISOString().slice(0, 10)}.pdf`);
  } catch (err) {
    console.error(err);
    alert('PDF export failed: ' + err.message);
  }
  msg.classList.remove('show');
}

/* ===== START ===== */
startRealtimeMonitoring();
render();

</script>

</body>
</html>