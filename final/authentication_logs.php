<?php
session_start();
include 'db.php';

if (empty($_SESSION['admin_logged_in']) && empty($_SESSION['officer_logged_in'])) {
    header("Location: login.php");
    exit;
}

/* Which role is viewing? Links carry ?from=admin or ?from=officer. We trust the link only if that role is
   really logged in, otherwise we use the remembered role, otherwise the role that logged in most recently.
   (One browser can hold both an admin and an officer login.) */
$navMap = [
  'admin'   => ['dash' => 'admin_dashboard.php',   'users' => 'users.php',         'sec' => 'manage_security.php',  'logs' => 'admin_logs.php',   'logout' => 'admin_logout.php',   'label' => 'Administrator'],
  'officer' => ['dash' => 'officer_dashboard.php', 'users' => 'officer_users.php', 'sec' => 'officer_security.php', 'logs' => 'officer_logs.php', 'logout' => 'officer_logout.php', 'label' => 'Security Officer'],
];
$loggedIn = ['admin' => !empty($_SESSION['admin_logged_in']), 'officer' => !empty($_SESSION['officer_logged_in'])];
$f = $_GET['from'] ?? '';
if (isset($loggedIn[$f]) && $loggedIn[$f]) {
    $_SESSION['auth_from'] = $f;
} else {
    $f = $_SESSION['auth_from'] ?? '';
    if (!isset($loggedIn[$f]) || !$loggedIn[$f]) {
        $last = $_SESSION['last_role'] ?? '';
        $f = (isset($loggedIn[$last]) && $loggedIn[$last]) ? $last : ($loggedIn['admin'] ? 'admin' : 'officer');
    }
}
$from = $f;
$nav  = $navMap[$from];

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/* ---------------- filters ---------------- */
$search = trim($_GET['search'] ?? '');
$status = strtoupper(trim($_GET['status'] ?? ''));
$action = strtoupper(trim($_GET['action'] ?? ''));
$date   = trim($_GET['date'] ?? '');

if (!in_array($status, ['SUCCESS', 'FAILED'], true)) $status = '';
if (!in_array($action, ['LOGIN', 'LOGOUT'], true))   $action = '';
if ($date !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) $date = '';

$where = []; $params = []; $types = '';
if ($search !== '') { $where[] = "username LIKE ?";        $params[] = "%{$search}%"; $types .= 's'; }
if ($status !== '') { $where[] = "UPPER(status) = ?";      $params[] = $status;       $types .= 's'; }
if ($action !== '') { $where[] = "UPPER(action) = ?";      $params[] = $action;       $types .= 's'; }
if ($date   !== '') { $where[] = "DATE(timestamp) = ?";    $params[] = $date;         $types .= 's'; }
$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

/* ---------------- totals (whole filtered set) ---------------- */
$total = $successful = $failed = 0;
try {
    $q = $conn->prepare("SELECT COUNT(*) AS t,
        COALESCE(SUM(UPPER(status)='SUCCESS'),0) AS ok,
        COALESCE(SUM(UPPER(status)<>'SUCCESS'),0) AS bad
        FROM (SELECT id, username_snapshot AS username, action, status, logged_at AS timestamp, ip_address FROM auth_logs) authentication_logs $whereSQL");
    if ($params) $q->bind_param($types, ...$params);
    $q->execute();
    $r = $q->get_result()->fetch_assoc();
    $total = (int)$r['t']; $successful = (int)$r['ok']; $failed = (int)$r['bad'];
} catch (Throwable $e) { error_log('auth logs totals: ' . $e->getMessage()); }

/* ---------------- pagination ---------------- */
$perPage = 50;
$pages   = max(1, (int)ceil($total / $perPage));
$page    = min(max(1, (int)($_GET['page'] ?? 1)), $pages);
$offset  = ($page - 1) * $perPage;

$logs = [];
try {
    $q = $conn->prepare("SELECT username, action, status, timestamp FROM (SELECT id, username_snapshot AS username, action, status, logged_at AS timestamp, ip_address FROM auth_logs) authentication_logs
        $whereSQL ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    $t2 = $types . 'ii'; $p2 = array_merge($params, [$perPage, $offset]);
    $q->bind_param($t2, ...$p2);
    $q->execute();
    $res = $q->get_result();
    while ($row = $res->fetch_assoc()) $logs[] = $row;
} catch (Throwable $e) { error_log('auth logs rows: ' . $e->getMessage()); }

/* ---------------- Failed Login Report (failures grouped by username and by IP) ---------------- */
// It has its own period tabs (fp) and does not use the search/status/date filters above.
$flrThreshold = 5;   // this many failures from one username or IP gets a "Repeated" badge
$flrPeriods = [
    'day'   => ['Today',        'CURDATE()'],
    'week'  => ['Last 7 days',  'CURDATE() - INTERVAL 6 DAY'],
    'month' => ['Last 30 days', 'CURDATE() - INTERVAL 29 DAY'],
    'all'   => ['All time',     null],
];
$fp = (string)($_GET['fp'] ?? 'week');
if (!isset($flrPeriods[$fp])) $fp = 'week';
$flrW = $flrPeriods[$fp][1] !== null ? " AND timestamp >= " . $flrPeriods[$fp][1] : "";

function flrRows($conn, $sql) {
    $out = [];
    try {
        $q = $conn->query($sql);
        while ($q && $row = $q->fetch_assoc()) $out[] = $row;
    } catch (Throwable $e) { error_log('failed login report: ' . $e->getMessage()); }
    return $out;
}

// Find the IP column, whatever it is called
$flrCols = [];
foreach (flrRows($conn, "SHOW COLUMNS FROM auth_logs") as $c) $flrCols[] = $c['Field'];
$flrIp = null;
foreach (['ip_address', 'ip', 'ipaddress', 'ip_addr', 'client_ip', 'remote_addr', 'user_ip'] as $c) {
    if (in_array($c, $flrCols, true)) { $flrIp = $c; break; }
}

$t = flrRows($conn, "SELECT COUNT(*) AS c, COUNT(DISTINCT username) AS u"
    . ($flrIp ? ", COUNT(DISTINCT NULLIF(`$flrIp`,'')) AS i" : ", 0 AS i")
    . " FROM (SELECT id, username_snapshot AS username, action, status, logged_at AS timestamp, ip_address FROM auth_logs) authentication_logs WHERE UPPER(status)='FAILED'$flrW");
$flrTotal = $t ? (int)$t[0]['c'] : 0;
$flrUsers = $t ? (int)$t[0]['u'] : 0;
$flrIps   = $t ? (int)$t[0]['i'] : 0;

$flrByUser = flrRows($conn, "SELECT username, COUNT(*) AS c, MIN(timestamp) AS first_at, MAX(timestamp) AS last_at"
    . ($flrIp ? ", COUNT(DISTINCT NULLIF(`$flrIp`,'')) AS ips" : ", 0 AS ips")
    . " FROM (SELECT id, username_snapshot AS username, action, status, logged_at AS timestamp, ip_address FROM auth_logs) authentication_logs WHERE UPPER(status)='FAILED'$flrW
      GROUP BY username ORDER BY c DESC, last_at DESC LIMIT 50");

$flrByIp = [];
if ($flrIp) {
    $flrByIp = flrRows($conn, "SELECT `$flrIp` AS ip, COUNT(*) AS c, COUNT(DISTINCT username) AS users,
        MIN(timestamp) AS first_at, MAX(timestamp) AS last_at
      FROM (SELECT id, username_snapshot AS username, action, status, logged_at AS timestamp, ip_address FROM auth_logs) authentication_logs WHERE UPPER(status)='FAILED' AND `$flrIp` IS NOT NULL AND `$flrIp` <> ''$flrW
      GROUP BY `$flrIp` ORDER BY c DESC, last_at DESC LIMIT 50");
}

$flrRepeat = 0;
foreach ($flrByUser as $r) if ((int)$r['c'] >= $flrThreshold) $flrRepeat++;

function pageUrl($n) {
    global $from;
    $q = $_GET; $q['page'] = $n; $q['from'] = $from;
    return '?' . http_build_query($q);
}

function icon($name) {
    $paths = [
        'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
        'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
        'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
        'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
        'chart'  => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
        'search' => '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
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
<title>Authentication Logs</title>
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
.sidebar .logout-item { margin-top: auto; }
.main { flex: 1; min-width: 0; padding: 32px; }
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }
.admin-badge { font-size: 12px; color: #6b7a94; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--line); background: #fff; }
.admin-badge .role { color: #d97706; font-weight: 600; }
.btn { display: inline-flex; align-items: center; gap: 8px; text-decoration: none; border-radius: 12px; border: 1px solid var(--line); background: #fff; color: var(--ink); font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; padding: 10px 16px; transition: transform .15s, background .15s, border-color .15s, box-shadow .15s; }
.btn svg { width: 16px; height: 16px; }
.btn:hover { transform: translateY(-1px); background: var(--gold-soft); border-color: var(--gold); box-shadow: var(--gold-glow); }
.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }
.cards { display: flex; gap: 16px; margin-bottom: 24px; }
.card { flex: 1; background: #fff; padding: 20px; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); transition: border-color .2s, box-shadow .2s; }
.card:hover { border-color: var(--gold); box-shadow: var(--gold-glow); }
.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.card h2 { font-size: 30px; margin-top: 8px; color: var(--navy); }
.filters { background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 18px; margin-bottom: 20px; display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.filter-group { display: flex; flex-direction: column; gap: 6px; }
.filter-group label { font-size: 11px; color: var(--muted); font-weight: 600; text-transform: uppercase; }
input, select { height: 40px; padding: 0 12px; border: 1px solid var(--line); border-radius: 9px; background: #fff; color: var(--ink); font-size: 13px; outline: none; }
input:focus, select:focus { border-color: var(--gold); box-shadow: 0 0 0 3px rgba(240,180,41,.12); }
.section { background: #fff; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px; }
.section h3 { font-size: 14px; margin-bottom: 18px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: .06em; padding: 0 12px 12px 0; }
td { padding: 13px 12px 13px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; }
.badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-success { background: #e8f8ef; color: #16a34a; }
.badge-failed { background: #fdeaea; color: #dc2626; }
.badge-action { background: #eef3fa; color: var(--navy); }
.badge-warn { background: #fff4db; color: #b45309; margin-left: 4px; }
.empty { color: #b7c3d6; text-align: center; padding: 30px; }
.pager { display: flex; justify-content: space-between; align-items: center; margin-top: 18px; font-size: 13px; color: var(--muted); gap: 12px; flex-wrap: wrap; }
.pager .btn[aria-disabled="true"] { opacity: .4; pointer-events: none; }

/* Failed Login Report */
.report { margin-bottom: 20px; }
.report h3 { margin-bottom: 4px; }
.report .hint { font-size: 12px; color: var(--muted); margin-bottom: 14px; }
.report .tabs { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
.report .tabs .btn { padding: 8px 14px; }
.report .cards { margin-bottom: 18px; }
.report .card { padding: 16px 18px; }
.report .card h2 { font-size: 26px; }
.report-grid { display: flex; gap: 16px; align-items: flex-start; }
.report-box { flex: 1; min-width: 0; border: 1px solid var(--line); border-radius: 12px; padding: 16px; }
.report-box h4 { font-size: 13px; font-weight: 600; margin-bottom: 2px; }
.report-box .hint { margin-bottom: 10px; }
.report-box th { padding-bottom: 8px; white-space: nowrap; }
.report-box td { padding: 10px 12px 10px 0; vertical-align: top; }
.report-box td.r, .report-box th.r { text-align: right; }
.report-box td small { display: block; font-size: 11px; color: var(--muted); margin-top: 2px; }
.report-box a.user { color: var(--navy); font-weight: 600; text-decoration: none; }
.report-box a.user:hover { text-decoration: underline; }
.report-empty { color: #b7c3d6; font-size: 13px; padding: 10px 0; }
.notice { background: #fff4db; border: 1px solid #f6d58a; color: #7a4b05; border-radius: 12px; padding: 12px 16px; font-size: 13px; margin-bottom: 16px; }

@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .main { padding: 20px; }
  .cards { flex-direction: column; }
  .report-grid { flex-direction: column; }
}
</style>
</head>
<body>

<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="<?= h($nav['dash']) ?>" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="<?= h($nav['users']) ?>" data-tip="Users" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item" href="<?= h($nav['sec']) ?>" data-tip="Security Accounts" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
  <a class="nav-item" href="<?= h($nav['logs']) ?>" data-tip="Access Logs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item" href="security_summary.php?from=<?= h($from) ?>" data-tip="Security Summary" aria-label="Security Summary"><span class="nav-icon"><?= icon('chart') ?></span><span class="nav-label">Security Summary</span></a>
  <a class="nav-item active" href="authentication_logs.php?from=<?= h($from) ?>" data-tip="Login Activity" aria-label="Login Activity" aria-current="page"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Login Activity</span></a>
  <a class="nav-item" href="activity_logs.php" data-tip="Security Activity" aria-label="Security Activity"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Security Activity</span></a>
  <a class="nav-item" href="active_sessions.php?from=<?= h($from) ?>" data-tip="Active Sessions" aria-label="Active Sessions"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Active Sessions</span></a>
  <a class="nav-item logout-item" href="<?= h($nav['logout']) ?>" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<main class="main">

  <div class="header">
    <div class="header-left">
      <h1>Activity Logs</h1>
      <p>Login and logout activity of security personnel</p>
    </div>
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <div class="admin-badge">Logged in as <span class="role"><?= h($nav['label']) ?></span></div>
      <a href="<?= h($nav['dash']) ?>" class="btn">Back to Dashboard</a>
    </div>
  </div>

  <div class="cards">
    <div class="card"><small>Total Records</small><h2><?= $total ?></h2></div>
    <div class="card"><small>Successful</small><h2><?= $successful ?></h2></div>
    <div class="card"><small>Failed</small><h2><?= $failed ?></h2></div>
  </div>

  <div class="section report" id="failed-login-report">
    <h3>Failed Login Report</h3>
    <p class="hint"><?= h($flrPeriods[$fp][0]) ?> · wrong username or password attempts, grouped. Click a username to see its failed attempts below.</p>

    <div class="tabs">
      <?php foreach ($flrPeriods as $key => $info): ?>
        <?php $tq = $_GET; unset($tq['page']); $tq['fp'] = $key; $tq['from'] = $from; ?>
        <a class="btn <?= $key === $fp ? 'btn-primary' : '' ?>" href="?<?= h(http_build_query($tq)) ?>#failed-login-report"><?= h($info[0]) ?></a>
      <?php endforeach; ?>
    </div>

    <?php if (!$flrIp): ?>
      <div class="notice"><strong>IP grouping is off.</strong> No IP column was found in <code>authentication_logs</code>, so only the by-username report works.</div>
    <?php endif; ?>

    <div class="cards">
      <div class="card"><small>Failed logins</small><h2><?= $flrTotal ?></h2></div>
      <div class="card"><small>Different usernames</small><h2><?= $flrUsers ?></h2></div>
      <div class="card"><small>Different IP addresses</small><h2><?= $flrIp ? $flrIps : '—' ?></h2></div>
      <div class="card"><small><?= (int)$flrThreshold ?>+ failures (usernames)</small><h2><?= $flrRepeat ?></h2></div>
    </div>

    <div class="report-grid">
      <div class="report-box">
        <h4>By username</h4>
        <p class="hint">A high count on one username can mean a forgotten password or someone guessing it.</p>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Username</th><th class="r">Failures</th><?php if ($flrIp): ?><th class="r">IPs</th><?php endif; ?><th>Last attempt</th></tr></thead>
            <tbody>
            <?php if (!$flrByUser): ?>
              <tr><td colspan="4" class="report-empty">No failed logins in this period</td></tr>
            <?php else: foreach ($flrByUser as $r): $c = (int)$r['c']; ?>
              <tr>
                <td>
                  <?php if ($r['username'] !== ''): ?>
                    <a class="user" href="?<?= h(http_build_query(['search' => $r['username'], 'status' => 'FAILED', 'from' => $from])) ?>"><?= h($r['username']) ?></a>
                  <?php else: ?>(blank)<?php endif; ?>
                  <?php if ($c >= $flrThreshold): ?><span class="badge badge-warn">Repeated</span><?php endif; ?>
                  <small>First: <?= h(date('M j, Y, g:i A', strtotime($r['first_at']))) ?></small>
                </td>
                <td class="r"><strong><?= $c ?></strong></td>
                <?php if ($flrIp): ?><td class="r"><?= (int)$r['ips'] ?></td><?php endif; ?>
                <td><?= h(date('M j, Y, g:i A', strtotime($r['last_at']))) ?></td>
              </tr>
            <?php endforeach; endif; ?>
            </tbody>
          </table>
        </div>
      </div>

      <div class="report-box">
        <h4>By IP address</h4>
        <p class="hint">One IP trying many usernames is a stronger warning sign than one username failing a few times.</p>
        <div class="table-wrap">
          <table>
            <thead><tr><th>IP address</th><th class="r">Failures</th><th class="r">Usernames</th><th>Last attempt</th></tr></thead>
            <tbody>
            <?php if (!$flrIp): ?>
              <tr><td colspan="4" class="report-empty">No IP column in authentication_logs</td></tr>
            <?php elseif (!$flrByIp): ?>
              <tr><td colspan="4" class="report-empty">No failed logins with a recorded IP in this period</td></tr>
            <?php else: foreach ($flrByIp as $r): $c = (int)$r['c']; $u = (int)$r['users']; ?>
              <tr>
                <td>
                  <?= h($r['ip']) ?>
                  <?php if ($c >= $flrThreshold): ?><span class="badge badge-warn">Repeated</span><?php endif; ?>
                  <?php if ($u >= 3): ?><span class="badge badge-failed" style="margin-left:4px">Many usernames</span><?php endif; ?>
                  <small>First: <?= h(date('M j, Y, g:i A', strtotime($r['first_at']))) ?></small>
                </td>
                <td class="r"><strong><?= $c ?></strong></td>
                <td class="r"><?= $u ?></td>
                <td><?= h(date('M j, Y, g:i A', strtotime($r['last_at']))) ?></td>
              </tr>
            <?php endforeach; endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <form method="GET" class="filters">
    <input type="hidden" name="from" value="<?= h($from) ?>">
    <input type="hidden" name="fp" value="<?= h($fp) ?>">
    <div class="filter-group">
      <label for="search">Search Username</label>
      <input type="text" id="search" name="search" placeholder="Enter username..." value="<?= h($search) ?>">
    </div>
    <div class="filter-group">
      <label for="action">Activity</label>
      <select id="action" name="action">
        <option value="">All Activity</option>
        <option value="LOGIN"  <?= $action === 'LOGIN'  ? 'selected' : '' ?>>Login</option>
        <option value="LOGOUT" <?= $action === 'LOGOUT' ? 'selected' : '' ?>>Logout</option>
      </select>
    </div>
    <div class="filter-group">
      <label for="status">Status</label>
      <select id="status" name="status">
        <option value="">All Status</option>
        <option value="SUCCESS" <?= $status === 'SUCCESS' ? 'selected' : '' ?>>Success</option>
        <option value="FAILED"  <?= $status === 'FAILED'  ? 'selected' : '' ?>>Failed</option>
      </select>
    </div>
    <div class="filter-group">
      <label for="date">Date</label>
      <input type="date" id="date" name="date" value="<?= h($date) ?>">
    </div>
    <button type="submit" class="btn btn-primary"><?= icon('search') ?> Filter</button>
    <a href="authentication_logs.php?from=<?= h($from) ?>" class="btn">Clear</a>
  </form>

  <div class="section">
    <h3>All Security Authentication Activity</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>#</th><th>Security Personnel</th><th>Activity</th><th>Status</th><th>Date &amp; Time</th></tr></thead>
        <tbody>
        <?php if ($logs): foreach ($logs as $i => $log):
            $ls = strtoupper((string)$log['status']);
            $cls = $ls === 'SUCCESS' ? 'badge-success' : 'badge-failed'; ?>
          <tr>
            <td><?= $offset + $i + 1 ?></td>
            <td><strong><?= h($log['username']) ?></strong></td>
            <td><span class="badge badge-action"><?= h($log['action']) ?></span></td>
            <td><span class="badge <?= $cls ?>"><?= h($ls) ?></span></td>
            <td><?= h(date('M j, Y, g:i A', strtotime($log['timestamp']))) ?></td>
          </tr>
        <?php endforeach; else: ?>
          <tr><td colspan="5" class="empty">No authentication records found.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>

    <div class="pager">
      <span>Page <?= $page ?> of <?= $pages ?> · <?= $total ?> records</span>
      <span style="display:flex;gap:8px">
        <a class="btn" href="<?= h(pageUrl($page - 1)) ?>" <?= $page <= 1 ? 'aria-disabled="true"' : '' ?>>Previous</a>
        <a class="btn" href="<?= h(pageUrl($page + 1)) ?>" <?= $page >= $pages ? 'aria-disabled="true"' : '' ?>>Next</a>
      </span>
    </div>
  </div>

</main>
</body>
</html>