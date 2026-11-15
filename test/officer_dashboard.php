<?php
session_start();
include 'db.php';
require_once __DIR__ . '/dashboard_flags.php';

if (!isset($_SESSION['officer_logged_in'])) {
    header("Location: login.php");
    exit;
}

$totalUsers = (int)$conn->query("
    SELECT COUNT(*) AS c FROM users
")->fetch_assoc()['c'];

$totalSecurity = (int)$conn->query("
    SELECT COUNT(*) AS c FROM security
")->fetch_assoc()['c'];

$todayLogs = (int)$conn->query("
    SELECT COUNT(*) AS c FROM logs WHERE DATE(timestamp) = CURDATE()
")->fetch_assoc()['c'];

$users = $conn->query("
    SELECT first_name, last_name, role FROM users LIMIT 5
");

$security = $conn->query("
    SELECT username FROM security LIMIT 5
");

$loginLogs = $conn->query("
    SELECT username, action, status, timestamp
    FROM authentication_logs ORDER BY timestamp DESC LIMIT 5
");

function icon($name) {
    $paths = [
        'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
        'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
        'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
        'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
        'chart'  => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
        'logout' => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    ];
    return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Officer Dashboard</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root { --ink: #16233d; --navy: #1c3a5e; --line: #dce4ef; --muted: #8a9bb5; --gold: #f0b429; --gold-soft: #fffdf5; --gold-glow: 0 8px 24px rgba(240,180,41,0.25); }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fafbfd; min-height: 100vh; display: flex; color: var(--ink); }
svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.sidebar { width: 220px; flex-shrink: 0; background: linear-gradient(180deg, #1c3a5e, #0f2440); border-right: 1px solid #0f2440; height: 100vh; position: sticky; top: 0; display: flex; flex-direction: column; align-items: stretch; padding: 24px 18px; gap: 12px; }
.sidebar .logo { display: flex; justify-content: center; }
.sidebar .logo img { width: 44px; height: 44px; border-radius: 12px; object-fit: cover; }
.sidebar-divider { width: 100%; height: 1px; background: rgba(255,255,255,0.12); margin: 4px 0; }
.sidebar .nav-item { display: flex; align-items: center; gap: 14px; width: 100%; color: #fff; text-decoration: none; font-size: 14px; font-weight: 500; white-space: nowrap; position: relative; }
.sidebar .nav-icon { width: 44px; height: 44px; border-radius: 12px; flex-shrink: 0; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12); display: flex; align-items: center; justify-content: center; transition: background .2s, border-color .2s, transform .2s; }
.sidebar .nav-icon svg { width: 20px; height: 20px; }
.sidebar .nav-label { color: rgba(255,255,255,0.85); overflow: hidden; text-overflow: ellipsis; }
.sidebar .nav-item:hover .nav-icon { background: rgba(240,180,41,0.18); border-color: var(--gold); transform: translateY(-1px); }
.sidebar .nav-item.active .nav-icon { background: rgba(240,180,41,0.25); border-color: var(--gold); }
.sidebar .nav-item.active .nav-label { color: #fff; font-weight: 600; }
.sidebar .nav-item:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; border-radius: 12px; }
.sidebar .logout-item { margin-top: auto; }
.main { flex: 1; min-width: 0; padding: 32px; }
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }
.header-right { display: flex; align-items: center; gap: 12px; }
.admin-badge { font-size: 12px; color: #6b7a94; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--line); background: #fff; }
.admin-badge .role { color: #d97706; font-weight: 600; }
.live-status { margin-left: 10px; color: #16a34a; font-weight: 600; }
.live-status.offline { color: #dc2626; }
.btn, .logout { display: inline-block; text-decoration: none; border-radius: 12px; border: 1px solid var(--line); background: #fff; color: var(--ink); font-size: 13px; font-weight: 600; cursor: pointer; transition: transform .15s, background .15s, border-color .15s, box-shadow .15s; }
.btn { padding: 11px 20px; }
.logout { padding: 8px 16px; font-weight: 500; }
.btn:hover, .logout:hover { transform: translateY(-2px); background: var(--gold-soft); border-color: var(--gold); box-shadow: var(--gold-glow); }
.btn:focus-visible, .logout:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }
.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }
.cards { display: flex; gap: 16px; margin-bottom: 24px; }
.card { flex: 1; background: #fff; padding: 20px; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); transition: border-color .2s, box-shadow .2s; }
.card:hover { border-color: var(--gold); box-shadow: var(--gold-glow); }
.card .icon { width: 40px; height: 40px; margin-bottom: 12px; border-radius: 12px; border: 2px dashed #c7d7ec; background: #f4f7fb; display: flex; align-items: center; justify-content: center; color: var(--navy); }
.card .icon svg { width: 20px; height: 20px; }
.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.card h2 { font-size: 32px; font-weight: 700; margin-top: 8px; color: var(--navy); }
.actions { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
.actions .btn { display: inline-flex; align-items: center; gap: 8px; }
.actions .btn svg { width: 16px; height: 16px; }
.sections { display: flex; gap: 16px; margin-bottom: 24px; }
.section, .section-full { background: #fff; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px; }
.section { flex: 1; min-width: 0; }
.section-full { margin-bottom: 24px; }
.section h3, .section-full h3 { font-size: 14px; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.section h3 a, .section-full h3 a { font-size: 12px; font-weight: 500; color: var(--muted); text-decoration: none; transition: color .2s; }
.section h3 a:hover, .section-full h3 a:hover { color: #d99a0b; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: 0.06em; padding-bottom: 10px; }
td { padding: 10px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; }
tr:hover td { color: var(--ink); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-in { background: #e8f8ef; color: #16a34a; }
.badge-out { background: #fdeaea; color: #dc2626; }
.badge-denied { background: #dc2626; color: #fff; }
.badge-admin { background: #fdf1d8; color: #d97706; }
.badge-security { background: #eef3fa; color: var(--navy); }
.badge-success { background: #e8f8ef; color: #16a34a; }
.badge-failed { background: #fdeaea; color: #dc2626; }
.flag-mark { margin-left: 6px; font-size: 11px; font-weight: 700; color: #b91c1c; }
.log-reason { display: block; font-size: 11px; color: #96a6c0; font-weight: 500; margin-top: 2px; }
.flagged-section { border-color: #f3b4b4; }
.flagged-section h3 { color: #b91c1c; }
.empty { color: #b7c3d6; font-size: 13px; padding: 12px 0; }
.realtime-new { animation: newActivity .7s ease; }
@keyframes newActivity { 0% { background: #fff8dc; } 100% { background: transparent; } }
@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .sidebar .logo img { width: 40px; height: 40px; }
  .nav-item::after { content: attr(data-tip); position: absolute; left: 54px; background: var(--ink); color: #fff; font-size: 11px; padding: 4px 10px; border-radius: 6px; white-space: nowrap; border: 1px solid rgba(255,255,255,0.1); opacity: 0; pointer-events: none; transition: opacity .15s; z-index: 100; }
  .nav-item:hover::after, .nav-item:focus-visible::after { opacity: 1; }
  .main { padding: 20px; }
  .cards, .sections { flex-direction: column; }
}
@media (prefers-reduced-motion: reduce) { .btn, .logout, .card, .sidebar .nav-icon { transition: none; } }
</style>
</head>

<body>

<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item active" href="officer_dashboard.php" data-tip="Dashboard" aria-label="Dashboard" aria-current="page">
    <span class="nav-icon"><?= icon('home') ?></span>
    <span class="nav-label">Dashboard</span>
  </a>
  <a class="nav-item" href="officer_users.php" data-tip="Users" aria-label="Users">
    <span class="nav-icon"><?= icon('user') ?></span>
    <span class="nav-label">Users</span>
  </a>
  <a class="nav-item" href="officer_security.php" data-tip="Security Accounts" aria-label="Security Accounts">
    <span class="nav-icon"><?= icon('lock') ?></span>
    <span class="nav-label">Security Accounts</span>
  </a>
  <a class="nav-item" href="officer_logs.php" data-tip="Logs" aria-label="Logs">
    <span class="nav-icon"><?= icon('list') ?></span>
    <span class="nav-label">Access Logs</span>
  </a>
  <a class="nav-item" href="security_summary.php?from=officer" data-tip="Security Summary" aria-label="Security Summary">
    <span class="nav-icon"><?= icon('chart') ?></span>
    <span class="nav-label">Security Summary</span>
  </a>
  <a class="nav-item" href="authentication_logs.php?from=officer" data-tip="Login Activity" aria-label="Login Activity">
    <span class="nav-icon"><?= icon('list') ?></span>
    <span class="nav-label">Activity Logs</span>
  </a>
  <a class="nav-item" href="active_sessions.php?from=officer" data-tip="Active Sessions" aria-label="Active Sessions">
    <span class="nav-icon"><?= icon('user') ?></span>
    <span class="nav-label">Active Sessions</span>
  </a>
  <a class="nav-item logout-item" href="officer_logout.php" data-tip="Logout" aria-label="Logout">
    <span class="nav-icon"><?= icon('logout') ?></span>
    <span class="nav-label">Logout</span>
  </a>
</nav>

<main class="main">

  <div class="header">
    <div class="header-left">
      <h1>Security Officer Dashboard</h1>
      <p><?= date('l, F j, Y') ?></p>
    </div>
    <div class="header-right">
      <div class="admin-badge">
        Logged in as <span class="role">Security Officer</span>
        <span id="liveStatus" class="live-status">● LIVE</span>
      </div>
    </div>
  </div>

  <div class="cards">
    <div class="card">
      <div class="icon"><?= icon('user') ?></div>
      <small>Total Campus Members</small>
      <h2 id="totalUsers"><?= $totalUsers ?></h2>
    </div>
    <div class="card">
      <div class="icon"><?= icon('lock') ?></div>
      <small>Security Personnel</small>
      <h2 id="totalSecurity"><?= $totalSecurity ?></h2>
    </div>
    <div class="card">
      <div class="icon"><?= icon('list') ?></div>
      <small>Activity Today</small>
      <h2 id="todayLogs"><?= $todayLogs ?></h2>
    </div>
  </div>

  <div class="actions">
    <a class="btn" href="officer_security.php"><?= icon('lock') ?> Manage Security</a>
    <a class="btn" href="officer_users.php"><?= icon('user') ?> Manage Users</a>
    <a class="btn" href="officer_logs.php"><?= icon('list') ?> View All Logs</a>
    <a class="btn" href="security_summary.php?from=officer"><?= icon('chart') ?> Security Summary</a>
  </div>

  <div class="sections">

    <div class="section">
      <h3>Registered Campus Members <a href="officer_users.php">View all</a></h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Role</th></tr></thead>
          <tbody>
          <?php if ($users && $users->num_rows > 0): ?>
            <?php while ($row = $users->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['first_name'] . " " . $row['last_name']) ?></td>
                <td><span class="badge badge-security"><?= htmlspecialchars($row['role']) ?></span></td>
              </tr>
            <?php endwhile; ?>
          <?php else: ?>
            <tr><td colspan="2" class="empty">No users registered</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h3>Security Accounts <a href="officer_security.php">Manage</a></h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Type</th></tr></thead>
          <tbody>
          <?php if ($security && $security->num_rows > 0): ?>
            <?php while ($row = $security->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['username']) ?></td>
                <td><span class="badge badge-admin">Security</span></td>
              </tr>
            <?php endwhile; ?>
          <?php else: ?>
            <tr><td colspan="2" class="empty">No security accounts</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <div class="section-full">
    <h3>Security Login Activity <a href="authentication_logs.php?from=officer">View all</a></h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Security Personnel</th><th>Activity</th><th>Status</th><th>Date & Time</th></tr></thead>
        <tbody id="authenticationLogsBody">
        <?php if ($loginLogs && $loginLogs->num_rows > 0): ?>
          <?php while ($row = $loginLogs->fetch_assoc()): ?>
            <?php $status = strtoupper($row['status']); $badgeClass = $status === 'SUCCESS' ? 'badge-success' : 'badge-failed'; ?>
            <tr>
              <td><?= htmlspecialchars($row['username']) ?></td>
              <td><?= htmlspecialchars($row['action']) ?></td>
              <td><span class="badge <?= $badgeClass ?>"><?= htmlspecialchars($status) ?></span></td>
              <td><?= htmlspecialchars(date('M j, Y, g:i A', strtotime($row['timestamp']))) ?></td>
            </tr>
          <?php endwhile; ?>
        <?php else: ?>
          <tr><td colspan="4" class="empty">No security login activity yet</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <div class="section-full flagged-section">
    <h3>Flagged Activity</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Reason</th><th>Denials</th><th>Time</th></tr></thead>
        <tbody id="flaggedBody"><?= dash_flagged_rows($conn, 5) ?></tbody>
      </table>
    </div>
  </div>

  <div class="section-full">
    <h3>Recent Activity <a href="officer_logs.php">View all</a></h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Status</th><th>Time</th></tr></thead>
        <tbody id="recentLogsBody"><?= dash_logs_rows($conn, 5) ?></tbody>
      </table>
    </div>
  </div>

</main>

<script>

let adminRealtimeRunning = false;

async function updateAdminDashboard() {
  if (adminRealtimeRunning) return;
  adminRealtimeRunning = true;
  const liveStatus = document.getElementById('liveStatus');

  try {
    const response = await fetch('realtime_dashboard.php?role=officer&_=' + Date.now(), {
      method: 'GET', cache: 'no-store', credentials: 'same-origin'
    });
    if (!response.ok) throw new Error('Server error');
    const data = await response.json();

    if (!data.success || data.role !== 'officer') throw new Error('Invalid dashboard response');

    liveStatus.textContent = '● LIVE';
    liveStatus.classList.remove('offline');

    document.getElementById('totalUsers').textContent    = data.stats.totalUsers;
    document.getElementById('totalSecurity').textContent = data.stats.totalSecurity;
    document.getElementById('todayLogs').textContent     = data.stats.todayLogs;

    const authBody = document.getElementById('authenticationLogsBody');
    if (authBody) {
      if (!data.authenticationLogs || data.authenticationLogs.length === 0) {
        authBody.innerHTML = `<tr><td colspan="4" class="empty">No security login activity yet</td></tr>`;
      } else {
        authBody.innerHTML = data.authenticationLogs.map(log => {
          const status = String(log.status).toUpperCase();
          const badgeClass = status === 'SUCCESS' ? 'badge-success' : 'badge-failed';
          return `<tr class="realtime-new">
            <td>${escapeHtml(log.username)}</td>
            <td>${escapeHtml(log.action)}</td>
            <td><span class="badge ${badgeClass}">${escapeHtml(status)}</span></td>
            <td>${escapeHtml(formatDateTime(log.timestamp))}</td>
          </tr>`;
        }).join('');
      }
    }

  } catch (error) {
    console.error('Realtime update failed:', error);
    liveStatus.textContent = '● OFFLINE';
    liveStatus.classList.add('offline');
  } finally {
    adminRealtimeRunning = false;
  }
}

/* Recent activity + flagged rows are built on the server (dashboard_flags.php) */
let flaggedRunning = false;

function setRows(id, html) {
  const el = document.getElementById(id);
  if (el && el.innerHTML !== html) el.innerHTML = html;
}

async function updateFlagged() {
  if (flaggedRunning) return;
  flaggedRunning = true;
  try {
    const res = await fetch('flagged_feed.php?limit=5&_=' + Date.now(), { cache: 'no-store', credentials: 'same-origin' });
    if (!res.ok) throw new Error('Feed error');
    const d = await res.json();
    if (!d.success) throw new Error('Feed error');
    setRows('recentLogsBody', d.logsHtml);
    setRows('flaggedBody', d.flaggedHtml);
  } catch (error) {
    console.error('Flagged feed failed:', error);
  } finally {
    flaggedRunning = false;
  }
}

function formatDateTime(value) {
  const date = new Date(String(value).replace(' ', 'T'));
  if (isNaN(date.getTime())) return value;
  return date.toLocaleString('en-US', { month:'short', day:'numeric', year:'numeric', hour:'numeric', minute:'2-digit' });
}

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = value ?? '';
  return div.innerHTML;
}

updateAdminDashboard();
updateFlagged();
setInterval(updateAdminDashboard, 3000);
setInterval(updateFlagged, 3000);

</script>

</body>
</html>