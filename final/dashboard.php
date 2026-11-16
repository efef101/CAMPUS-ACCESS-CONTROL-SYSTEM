<?php
session_start();
include 'db.php';
include_once 'auth.php';
require_once __DIR__ . '/dashboard_flags.php';

// The live refresh (?realtime=1) answers with JSON, so an expired session gets a JSON 401 instead of a redirect
if (isset($_GET['realtime']) && auth_role() !== 'personnel') {
  http_response_code(401);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['success' => false, 'message' => 'Session expired']);
  exit;
}

require_auth($conn, ['personnel']);

header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// ---- Live data for the dashboard (the page polls this every 3 seconds) ----
if (isset($_GET['realtime'])) {
  session_write_close();   // read-only request: don't hold the session lock while scanners are in use
  header('Content-Type: application/json; charset=utf-8');

  $usersInside = [];
  $r = $conn->query("SELECT first_name, last_name, role FROM people WHERE status = 'IN'");
  while ($r && $row = $r->fetch_assoc()) {
    $usersInside[] = ['name' => trim($row['first_name'] . ' ' . $row['last_name']), 'role' => $row['role']];
  }

  $visitorsInside = [];
  $r = $conn->query("SELECT name, purpose FROM visitors WHERE status = 'IN'");
  while ($r && $row = $r->fetch_assoc()) {
    $visitorsInside[] = ['name' => $row['name'], 'purpose' => $row['purpose']];
  }

  $recentCount = 0;
  $r = $conn->query("SELECT COUNT(*) AS c FROM (SELECT id FROM access_logs ORDER BY logged_at DESC LIMIT 10) t");
  if ($r && $row = $r->fetch_assoc()) $recentCount = (int)$row['c'];

  echo json_encode([
    'success' => true,
    'role'    => 'security',
    'stats'   => [
      'usersInside'    => count($usersInside),
      'visitorsInside' => count($visitorsInside),
      'recentLogs'     => $recentCount,
    ],
    'usersInside'    => $usersInside,
    'visitorsInside' => $visitorsInside,
    'logsHtml'       => dash_logs_rows($conn, 10),
    'flaggedHtml'    => dash_flagged_rows($conn, 5),
  ], JSON_UNESCAPED_UNICODE);
  exit;
}

// Only the columns the page shows (SELECT * would also pull face images into memory)
$logs     = $conn->query("SELECT id FROM access_logs ORDER BY logged_at DESC LIMIT 10");
$users    = $conn->query("SELECT first_name, last_name, role FROM people WHERE status = 'IN'");
$visitors = $conn->query("SELECT name, purpose FROM visitors WHERE status = 'IN'");


// Inline SVG icons (same set as the admin dashboard)
function icon($name) {
  $paths = [
    'home'    => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'user'    => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    'users'   => '<circle cx="9" cy="8" r="3.5"/><path d="M2 20c0-3.6 3-6 7-6s7 2.4 7 6"/><path d="M16 4.5a3.5 3.5 0 010 7M18 14.5c2.4.6 4 2.4 4 5.5"/>',
    'list'    => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'scan'    => '<path d="M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3"/><path d="M4 12h16"/>',
    'visitor' => '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6 16c.5-1.5 1.7-2 3-2s2.5.5 3 2M15 10h3M15 13h3"/>',
    'add'     => '<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6.5 7-6.5M18 14v6M15 17h6"/>',
    'mega'    => '<path d="M3 11v2a1 1 0 001 1h2l7 4V6L6 10H4a1 1 0 00-1 1z"/><path d="M16 9a4 4 0 010 6M19 7a7 7 0 010 10"/>',
    'camera'  => '<path d="M4 8h3l2-3h6l2 3h3a1 1 0 011 1v10a1 1 0 01-1 1H4a1 1 0 01-1-1V9a1 1 0 011-1z"/><circle cx="12" cy="13" r="3.5"/>',
    'patrol'  => '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    'logout'  => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
  ];
  return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Dashboard</title>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --ink: #16233d;
  --navy: #1c3a5e;
  --line: #dce4ef;
  --muted: #8a9bb5;
  --gold: #f0b429;
  --gold-soft: #fffdf5;
  --gold-glow: 0 8px 24px rgba(240,180,41,0.25);
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #fafbfd;
  min-height: 100vh;
  display: flex;
  color: var(--ink);
}

svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }

/* SIDEBAR */
.sidebar {
  width: 220px;
  flex-shrink: 0;
  background: linear-gradient(180deg, #1c3a5e, #0f2440);
  border-right: 1px solid #0f2440;
  height: 100vh;
  position: sticky;
  top: 0;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  padding: 24px 18px;
  gap: 12px;
}

.sidebar .logo { display: flex; justify-content: center; }

.sidebar .logo img {
  width: 44px; height: 44px; border-radius: 50%; object-fit: cover;
}

.sidebar-divider { width: 100%; height: 1px; background: rgba(255,255,255,0.12); margin: 4px 0; }

/* the row: [icon box] name */
.sidebar .nav-item {
  display: flex; align-items: center; gap: 14px;
  width: 100%;
  color: #fff; text-decoration: none;
  font-size: 14px; font-weight: 500; white-space: nowrap;
  position: relative;
}

/* the icon box */
.sidebar .nav-icon {
  width: 44px; height: 44px; border-radius: 12px; flex-shrink: 0;
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.12);
  display: flex; align-items: center; justify-content: center;
  transition: background .2s, border-color .2s, transform .2s;
}
.sidebar .nav-icon svg { width: 20px; height: 20px; }

.sidebar .nav-label { color: rgba(255,255,255,0.85); overflow: hidden; text-overflow: ellipsis; }

.sidebar .nav-item:hover .nav-icon {
  background: rgba(240,180,41,0.18);
  border-color: var(--gold);
  transform: translateY(-1px);
}
.sidebar .nav-item.active .nav-icon {
  background: rgba(240,180,41,0.25);
  border-color: var(--gold);
}
.sidebar .nav-item.active .nav-label { color: #fff; font-weight: 600; }
.sidebar .nav-item:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; border-radius: 12px; }
.sidebar .logout-item { margin-top: auto; }

/* MAIN */
.main { flex: 1; min-width: 0; padding: 32px; }

/* HEADER */
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }
.header-right { display: flex; align-items: center; gap: 12px; }

.admin-badge {
  font-size: 12px; color: #6b7a94; padding: 6px 12px;
  border-radius: 8px; border: 1px solid var(--line); background: #fff;
}
.admin-badge span { color: #d97706; font-weight: 600; }

.admin-badge .live-status {
  margin-left: 10px;
  color: #16a34a;
  font-weight: 700;
  letter-spacing: 0.04em;
}
.admin-badge .live-status.offline { color: #dc2626; }

/* Shared button look: white, soft border, yellow hover */
.btn, .logout {
  display: inline-block;
  text-decoration: none;
  border-radius: 12px;
  border: 1px solid var(--line);
  background: #fff;
  color: var(--ink);
  font-size: 13px; font-weight: 600;
  cursor: pointer;
  transition: transform .15s, background .15s, border-color .15s, box-shadow .15s;
}
.btn { padding: 11px 20px; }
.logout { padding: 8px 16px; font-weight: 500; }

.btn:hover, .logout:hover {
  transform: translateY(-2px);
  background: var(--gold-soft);
  border-color: var(--gold);
  box-shadow: var(--gold-glow);
}
.btn:focus-visible, .logout:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }

.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }

/* CARDS */
.cards { display: flex; gap: 16px; margin-bottom: 24px; }

.card {
  flex: 1;
  background: #fff; padding: 20px; border-radius: 14px;
  border: 1px solid var(--line);
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  transition: border-color .2s, box-shadow .2s;
}
.card:hover { border-color: var(--gold); box-shadow: var(--gold-glow); }

.card .icon {
  width: 40px; height: 40px; margin-bottom: 12px;
  border-radius: 12px; border: 2px dashed #c7d7ec; background: #f4f7fb;
  display: flex; align-items: center; justify-content: center; color: var(--navy);
}
.card .icon svg { width: 20px; height: 20px; }

.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.card h2 { font-size: 32px; font-weight: 700; margin-top: 8px; color: var(--navy); }

/* ACTION BUTTONS */
.actions { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
.actions .btn { display: inline-flex; align-items: center; gap: 8px; }
.actions .btn svg { width: 16px; height: 16px; }

/* SECTIONS */
.sections { display: flex; gap: 16px; margin-bottom: 24px; }

.section, .section-full {
  background: #fff; border-radius: 14px; border: 1px solid var(--line);
  box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px;
}
.section { flex: 1; min-width: 0; }
.section-full { margin-bottom: 24px; }

.section h3, .section-full h3 {
  font-size: 14px; font-weight: 600; margin-bottom: 16px;
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
}
.section h3 a, .section-full h3 a {
  font-size: 12px; font-weight: 500; color: var(--muted);
  text-decoration: none; transition: color .2s;
}
.section h3 a:hover, .section-full h3 a:hover { color: #d99a0b; }
.section h3 a:focus-visible, .section-full h3 a:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }

/* TABLE */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: 0.06em; padding-bottom: 10px; }
td { padding: 10px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; }
tr:hover td { color: var(--ink); }

.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-in       { background: #e8f8ef; color: #16a34a; }
.badge-out      { background: #fdeaea; color: #dc2626; }
.badge-denied   { background: #dc2626; color: #fff; }
.badge-security { background: #eef3fa; color: var(--navy); }

.flag-mark   { margin-left: 6px; font-size: 11px; font-weight: 700; color: #b91c1c; }
.log-reason  { display: block; font-size: 11px; color: #96a6c0; font-weight: 500; margin-top: 2px; }
.flagged-section { border-color: #f3b4b4; }
.flagged-section h3 { color: #b91c1c; }

.empty { color: #b7c3d6; font-size: 13px; padding: 12px 0; }

/* RESPONSIVE */
@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .sidebar .logo { justify-content: center; }
  .sidebar .logo img { width: 40px; height: 40px; }

  /* Tooltip (names are hidden at this size) */
  .nav-item::after {
    content: attr(data-tip);
    position: absolute; left: 54px;
    background: var(--ink); color: #fff;
    font-size: 11px; padding: 4px 10px; border-radius: 6px; white-space: nowrap;
    border: 1px solid rgba(255,255,255,0.1);
    opacity: 0; pointer-events: none; transition: opacity .15s; z-index: 100;
  }
  .nav-item:hover::after, .nav-item:focus-visible::after { opacity: 1; }
  .main { padding: 20px; }
  .cards, .sections { flex-direction: column; }
}

@media (prefers-reduced-motion: reduce) {
  .btn, .logout, .card, .sidebar .nav-icon { transition: none; }
}
</style>

<!-- Phone layout (bottom tab bar, compact cards). Must stay AFTER the <style> block above. -->
<link rel="stylesheet" href="mobile.css">
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item active" href="dashboard.php" data-tip="Dashboard" aria-label="Dashboard" aria-current="page"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="security_logs.php" data-tip="Logs" aria-label="Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item" href="visitor_register.php" data-tip="Register Visitor" aria-label="Register Visitor"><span class="nav-icon"><?= icon('visitor') ?></span><span class="nav-label">Register Visitor</span></a>
  <a class="nav-item" href="announcements.php" data-tip="Announcements" aria-label="Announcements"><span class="nav-icon"><?= icon('mega') ?></span><span class="nav-label">Announcements</span></a>
  <a class="nav-item logout-item" href="security_logout.php" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<!-- MAIN -->
<main class="main">

  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <h1>Security Personnel Dashboard</h1>
      <p><?= date('l, F j, Y') ?></p>
    </div>
    <div class="header-right">
      <div class="admin-badge">
        Logged in as <span>Security Personnel</span>
        <span id="liveStatus" class="live-status">● LIVE</span>
      </div>
    </div>
  </div>

  <!-- CARDS -->
  <div class="cards">
    <div class="card">
      <div class="icon"><?= icon('user') ?></div>
      <small>Campus Members Inside</small>
      <h2 id="usersInsideCount"><?= $users->num_rows ?></h2>
    </div>
    <div class="card">
      <div class="icon"><?= icon('users') ?></div>
      <small>Visitors Inside</small>
      <h2 id="visitorsInsideCount"><?= $visitors->num_rows ?></h2>
    </div>
    <div class="card">
      <div class="icon"><?= icon('list') ?></div>
      <small>Recent Logs</small>
      <h2 id="recentLogsCount"><?= $logs->num_rows ?></h2>
    </div>
  </div>

  <!-- ACTIONS -->
  <div class="actions">
    <a class="btn btn-primary" href="scanner_hw.php"><?= icon('scan') ?> Start Scanning</a>
    <a class="btn" href="scanner_hw.php?camera=1"><?= icon('camera') ?> Camera Backup</a>
    <a class="btn" href="mobile_scanning.php"><?= icon('patrol') ?> Patrol ID Check</a>
  </div>

  <!-- USERS + VISITORS -->
  <div class="sections">

    <div class="section">
      <h3>Campus Members Inside</h3>
      <div class="table-wrap">
        <table>
          <tr><th>Name</th><th>Role</th></tr>
          <tbody id="usersInsideBody">
            <?php if ($users && $users->num_rows > 0): while ($row = $users->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['first_name'] . " " . $row['last_name']) ?></td>
                <td><span class="badge badge-security"><?= htmlspecialchars($row['role']) ?></span></td>
              </tr>
            <?php endwhile; else: ?>
              <tr><td colspan="2" class="empty">No users inside</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h3>Visitors Inside</h3>
      <div class="table-wrap">
        <table>
          <tr><th>Name</th><th>Purpose</th></tr>
          <tbody id="visitorsInsideBody">
            <?php if ($visitors && $visitors->num_rows > 0): while ($row = $visitors->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['name']) ?></td>
                <td><?= htmlspecialchars($row['purpose']) ?></td>
              </tr>
            <?php endwhile; else: ?>
              <tr><td colspan="2" class="empty">No visitors inside</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <!-- FLAGGED ACTIVITY -->
  <div class="section-full flagged-section">
    <h3>Flagged Activity</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Reason</th><th>Denials</th><th>Time</th></tr></thead>
        <tbody id="flaggedBody"><?= dash_flagged_rows($conn, 5) ?></tbody>
      </table>
    </div>
  </div>

  <!-- RECENT LOGS -->
  <div class="section-full">
    <h3>Recent Logs <a href="security_logs.php">View all</a></h3>
    <div class="table-wrap">
      <table>
        <tr><th>Name</th><th>Status</th><th>Time</th></tr>
        <tbody id="recentLogsBody"><?= dash_logs_rows($conn, 10) ?></tbody>
      </table>
    </div>
  </div>

</main>

<script>
let securityRealtimeRunning = false;

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }[char]));
}

function setRows(id, html) {
  const el = document.getElementById(id);
  if (el && el.innerHTML !== html) el.innerHTML = html;
}

async function updateSecurityDashboard() {
  if (securityRealtimeRunning) return;
  securityRealtimeRunning = true;

  const liveStatus = document.getElementById('liveStatus');

  try {
    // The live data now comes from this same file (see the ?realtime block at the top)
    const response = await fetch('dashboard.php?realtime=1&_=' + Date.now(), {
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin'
    });

    if (!response.ok) throw new Error('Server error');

    const data = await response.json();

    if (!data.success || data.role !== 'security') {
      throw new Error('Invalid dashboard response');
    }

    liveStatus.textContent = '● LIVE';
    liveStatus.classList.remove('offline');

    document.getElementById('usersInsideCount').textContent = data.stats.usersInside;
    document.getElementById('visitorsInsideCount').textContent = data.stats.visitorsInside;
    document.getElementById('recentLogsCount').textContent = data.stats.recentLogs;

    const usersBody = document.getElementById('usersInsideBody');
    if (usersBody) {
      if (!data.usersInside || data.usersInside.length === 0) {
        usersBody.innerHTML = '<tr><td colspan="2" class="empty">No users inside</td></tr>';
      } else {
        usersBody.innerHTML = data.usersInside.map(item => `
          <tr>
            <td>${escapeHtml(item.name)}</td>
            <td><span class="badge badge-security">${escapeHtml(item.role)}</span></td>
          </tr>
        `).join('');
      }
    }

    const visitorsBody = document.getElementById('visitorsInsideBody');
    if (visitorsBody) {
      if (!data.visitorsInside || data.visitorsInside.length === 0) {
        visitorsBody.innerHTML = '<tr><td colspan="2" class="empty">No visitors inside</td></tr>';
      } else {
        visitorsBody.innerHTML = data.visitorsInside.map(item => `
          <tr>
            <td>${escapeHtml(item.name)}</td>
            <td>${escapeHtml(item.purpose)}</td>
          </tr>
        `).join('');
      }
    }

    // Recent logs and flagged rows are built on the server (dashboard_flags.php)
    setRows('recentLogsBody', data.logsHtml);
    setRows('flaggedBody', data.flaggedHtml);

  } catch (error) {
    console.error('Security realtime update failed:', error);
    liveStatus.textContent = '● OFFLINE';
    liveStatus.classList.add('offline');
  } finally {
    securityRealtimeRunning = false;
  }
}

updateSecurityDashboard();
setInterval(updateSecurityDashboard, 3000);
</script>

</body>
</html>