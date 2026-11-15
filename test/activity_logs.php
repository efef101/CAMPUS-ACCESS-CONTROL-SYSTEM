<?php
session_start();
include 'db.php';

// Administrator only (matches the module table: User Activity Logs is an admin feature)
if (empty($_SESSION['admin_logged_in'])) {
  header("Location: login.php");
  exit;
}
header("Cache-Control: no-cache, no-store, must-revalidate");

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/* ---------------- filters ---------------- */
$search = trim((string)($_GET['search'] ?? ''));
$action = trim((string)($_GET['action'] ?? ''));
$date   = trim((string)($_GET['date'] ?? ''));
$search = function_exists('mb_substr') ? mb_substr($search, 0, 60) : substr($search, 0, 60);

$actions = [
  'CREATE ACCOUNT'     => 'Created security account',
  'RESET PASSWORD'     => 'Reset password',
  'ACTIVATE ACCOUNT'   => 'Activated account',
  'DEACTIVATE ACCOUNT' => 'Deactivated account',
  'DELETE ACCOUNT'     => 'Deleted account',
  'MARK ALUMNI'        => 'Marked as alumni',
  'UNDO ALUMNI'        => 'Undid alumni',
  'POST ANNOUNCEMENT'  => 'Posted announcement',
  'HIDE ANNOUNCEMENT'  => 'Hid announcement',
  'SHOW ANNOUNCEMENT'  => 'Showed announcement',
  'DELETE ANNOUNCEMENT'=> 'Deleted announcement',
  'REGISTER VISITOR'   => 'Registered visitor',
];
if ($action !== '' && !isset($actions[$action])) $action = '';
if ($date !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) $date = '';

$where = []; $params = []; $types = '';
if ($search !== '') {
  $where[] = "(actor LIKE ? OR target LIKE ? OR details LIKE ?)";
  $like = '%' . addcslashes($search, '%_') . '%';
  array_push($params, $like, $like, $like); $types .= 'sss';
}
if ($action !== '') { $where[] = "action = ?";           $params[] = $action; $types .= 's'; }
if ($date   !== '') { $where[] = "DATE(created_at) = ?"; $params[] = $date;   $types .= 's'; }
$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

/* ---------------- cards (whole table, not just the filtered rows) ---------------- */
$cTotal = $cToday = $cActors = 0;
$cLast = '-';
$tableMissing = false;
try {
  $r = $conn->query("SELECT COUNT(*) AS t,
                            COALESCE(SUM(DATE(created_at) = CURDATE()),0) AS d,
                            COUNT(DISTINCT actor) AS a,
                            MAX(created_at) AS l
                     FROM activity_logs")->fetch_assoc();
  $cTotal = (int)$r['t']; $cToday = (int)$r['d']; $cActors = (int)$r['a'];
  if ($r['l']) $cLast = date('M j, g:i A', strtotime($r['l']));
} catch (Throwable $e) {
  $tableMissing = true;
  error_log('activity cards: ' . $e->getMessage());
}

/* ---------------- rows + pagination ---------------- */
$total = 0;
$rows = [];
if (!$tableMissing) {
  try {
    $q = $conn->prepare("SELECT COUNT(*) FROM activity_logs $whereSQL");
    if ($params) $q->bind_param($types, ...$params);
    $q->execute();
    $q->bind_result($total);
    $q->fetch();
    $q->close();
  } catch (Throwable $e) { error_log('activity count: ' . $e->getMessage()); }
}
$perPage = 50;
$pages   = max(1, (int)ceil($total / $perPage));
$page    = min(max(1, (int)($_GET['page'] ?? 1)), $pages);
$offset  = ($page - 1) * $perPage;

if (!$tableMissing) {
  try {
    $q = $conn->prepare("SELECT actor, actor_role, action, target, details, ip_address, created_at
                         FROM activity_logs $whereSQL ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?");
    $t2 = $types . 'ii'; $p2 = array_merge($params, [$perPage, $offset]);
    $q->bind_param($t2, ...$p2);
    $q->execute();
    $res = $q->get_result();
    while ($row = $res->fetch_assoc()) $rows[] = $row;
    $q->close();
  } catch (Throwable $e) { error_log('activity rows: ' . $e->getMessage()); }
}

function pageUrl($n) { $q = $_GET; $q['page'] = $n; return '?' . http_build_query($q); }

function icon($name) {
  $paths = [
    'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'chart'  => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    'logout' => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    'search' => '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
  ];
  return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}

// badge colour per kind of action
function actionClass($a) {
  if ($a === 'DELETE ACCOUNT' || $a === 'DEACTIVATE ACCOUNT') return 'b-red';
  if ($a === 'RESET PASSWORD') return 'b-amber';
  if ($a === 'CREATE ACCOUNT' || $a === 'ACTIVATE ACCOUNT' || $a === 'REGISTER VISITOR') return 'b-green';
  return 'b-blue';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>User Activity Logs</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root { --ink: #16233d; --navy: #1c3a5e; --line: #dce4ef; --muted: #8a9bb5; --gold: #f0b429; --gold-soft: #fffdf5; --gold-glow: 0 8px 24px rgba(240,180,41,0.25); }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fafbfd; min-height: 100vh; display: flex; color: var(--ink); }
svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.sidebar { width: 220px; flex-shrink: 0; background: linear-gradient(180deg, #1c3a5e, #0f2440); border-right: 1px solid #0f2440; height: 100vh; position: sticky; top: 0; display: flex; flex-direction: column; align-items: stretch; padding: 24px 18px; gap: 12px; overflow-y: auto; }
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
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }
.admin-badge { font-size: 12px; color: #6b7a94; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--line); background: #fff; }
.admin-badge .role { color: #d97706; font-weight: 600; }
.btn { display: inline-flex; align-items: center; gap: 8px; text-decoration: none; border-radius: 12px; border: 1px solid var(--line); background: #fff; color: var(--ink); font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; padding: 10px 16px; transition: transform .15s, background .15s, border-color .15s, box-shadow .15s; }
.btn svg { width: 16px; height: 16px; }
.btn:hover { transform: translateY(-1px); background: var(--gold-soft); border-color: var(--gold); box-shadow: var(--gold-glow); }
.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #fff; padding: 18px 20px; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); }
.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.card h2 { font-size: 30px; margin-top: 6px; color: var(--navy); font-variant-numeric: tabular-nums; }
.card h2.small { font-size: 16px; margin-top: 14px; }
.filters { background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 18px; margin-bottom: 20px; display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.filter-group { display: flex; flex-direction: column; gap: 6px; }
.filter-group.grow { flex: 1; min-width: 200px; }
.filter-group label { font-size: 11px; color: var(--muted); font-weight: 600; text-transform: uppercase; }
input, select { height: 40px; padding: 0 12px; border: 1px solid var(--line); border-radius: 9px; background: #fff; color: var(--ink); font-size: 13px; outline: none; font-family: inherit; }
.filter-group.grow input { width: 100%; }
input:focus, select:focus { border-color: var(--gold); box-shadow: 0 0 0 3px rgba(240,180,41,.12); }
.section { background: #fff; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px; }
.section h3 { font-size: 14px; margin-bottom: 4px; }
.section .hint { font-size: 12px; color: var(--muted); margin-bottom: 16px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: .06em; padding: 0 12px 12px 0; white-space: nowrap; }
td { padding: 12px 12px 12px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; vertical-align: top; }
td small { display: block; font-size: 11px; color: var(--muted); margin-top: 2px; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
.b-blue { background: #eef3fa; color: var(--navy); }
.b-green { background: #e8f8ef; color: #16a34a; }
.b-amber { background: #fff4db; color: #b45309; }
.b-red { background: #fdeaea; color: #dc2626; }
.empty { color: #b7c3d6; text-align: center; padding: 30px; }
.notice { background: #fff4db; border: 1px solid #f6d58a; color: #7a4b05; border-radius: 12px; padding: 12px 16px; font-size: 13px; margin-bottom: 16px; }
.pager { display: flex; justify-content: space-between; align-items: center; margin-top: 18px; font-size: 13px; color: var(--muted); gap: 12px; flex-wrap: wrap; }
.pager .btn[aria-disabled="true"] { opacity: .4; pointer-events: none; }
@media (max-width: 860px) { .sidebar { width: 64px; padding: 24px 10px; } .sidebar .nav-label { display: none; } .main { padding: 20px; } }
</style>
</head>
<body>

<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="admin_dashboard.php" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="users.php" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item" href="manage_security.php" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
  <a class="nav-item" href="admin_logs.php" aria-label="Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Logs</span></a>
  <a class="nav-item" href="security_summary.php?from=admin" aria-label="Security Summary"><span class="nav-icon"><?= icon('chart') ?></span><span class="nav-label">Security Summary</span></a>
  <a class="nav-item" href="authentication_logs.php?from=admin" aria-label="Login Activity"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Login Activity</span></a>
  <a class="nav-item" href="active_sessions.php?from=admin" aria-label="Active Sessions"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Active Sessions</span></a>
  <a class="nav-item active" href="activity_logs.php" aria-label="Activity Logs" aria-current="page"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Activity Logs</span></a>
  <a class="nav-item logout-item" href="admin_logout.php" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<main class="main">
  <div class="header">
    <div class="header-left">
      <h1>User Activity Logs</h1>
      <p>What administrators, officers and personnel did: account changes, alumni updates and visitor registrations</p>
    </div>
    <div class="admin-badge">Logged in as <span class="role">Administrator</span></div>
  </div>

  <?php if ($tableMissing): ?>
    <div class="notice"><strong>The activity table does not exist yet.</strong> Run <code>activity_logs_database.sql</code> once in phpMyAdmin, then reload this page.</div>
  <?php endif; ?>

  <div class="cards">
    <div class="card"><small>Total actions</small><h2><?= $cTotal ?></h2></div>
    <div class="card"><small>Today</small><h2><?= $cToday ?></h2></div>
    <div class="card"><small>People who acted</small><h2><?= $cActors ?></h2></div>
    <div class="card"><small>Latest action</small><h2 class="small"><?= h($cLast) ?></h2></div>
  </div>

  <form method="GET" class="filters">
    <div class="filter-group grow">
      <label for="search">Search</label>
      <input type="text" id="search" name="search" maxlength="60" placeholder="Who did it, or who it was done to..." value="<?= h($search) ?>">
    </div>
    <div class="filter-group">
      <label for="action">Action</label>
      <select id="action" name="action">
        <option value="">All actions</option>
        <?php foreach ($actions as $k => $label): ?>
          <option value="<?= h($k) ?>" <?= $action === $k ? 'selected' : '' ?>><?= h($label) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div class="filter-group">
      <label for="date">Date</label>
      <input type="date" id="date" name="date" value="<?= h($date) ?>">
    </div>
    <button type="submit" class="btn btn-primary"><?= icon('search') ?> Filter</button>
    <a href="activity_logs.php" class="btn">Clear</a>
  </form>

  <div class="section">
    <h3>All Recorded Actions</h3>
    <p class="hint">Newest first. Login and logout are in Login Activity, not here.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>#</th><th>Date &amp; Time</th><th>Done by</th><th>Action</th><th>Done to</th><th>IP address</th></tr></thead>
        <tbody>
        <?php if ($rows): foreach ($rows as $i => $row): ?>
          <tr>
            <td><?= $offset + $i + 1 ?></td>
            <td><?= h(date('M j, Y, g:i A', strtotime($row['created_at']))) ?></td>
            <td><strong><?= h($row['actor']) ?></strong><small><?= h($row['actor_role']) ?></small></td>
            <td><span class="badge <?= actionClass($row['action']) ?>"><?= h($actions[$row['action']] ?? $row['action']) ?></span></td>
            <td><?= $row['target'] !== null && $row['target'] !== '' ? h($row['target']) : '-' ?><?php if (!empty($row['details'])): ?><small><?= h($row['details']) ?></small><?php endif; ?></td>
            <td><?= h($row['ip_address'] ?: '-') ?></td>
          </tr>
        <?php endforeach; else: ?>
          <tr><td colspan="6" class="empty"><?= $tableMissing ? 'Activity table not created yet.' : 'No activity recorded yet.' ?></td></tr>
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