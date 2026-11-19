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
if ($from !== 'admin') {   // Activity Logs is admin-only
  if (!$loggedIn['admin']) { header("Location: officer_dashboard.php"); exit; }
  $from = 'admin';
  $nav  = $navMap['admin'];
}

// Logged-in username for the sidebar badge
$loggedName = ($from === 'admin') ? ($_SESSION['admin_username'] ?? 'Admin') : ($_SESSION['officer_username'] ?? 'Officer');

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

// Which sub-tab: Login Activity (default) or Security Activity. A real navigation (not a client-side
// toggle), so each tab only runs its own queries and keeps its own filters/pagination in the URL.
$tab = ($_GET['tab'] ?? 'login') === 'activity' ? 'activity' : 'login';

function icon($name) {
    $paths = [
        'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
        'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
        'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
        'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
        'chart'  => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
        'search' => '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
        'filter' => '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
        'logout' => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    ];
    return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}

/* =========================================================================
   LOGIN ACTIVITY TAB (prefixed la_ to avoid colliding with the Security
   Activity tab's own filters, since both tabs' forms live on one URL).
========================================================================= */
if ($tab === 'login') {

  $la_search = trim($_GET['la_search'] ?? '');
  $la_status = strtoupper(trim($_GET['la_status'] ?? ''));
  $la_action = strtoupper(trim($_GET['la_action'] ?? ''));
  $la_date   = trim($_GET['la_date'] ?? '');

  if (!in_array($la_status, ['SUCCESS', 'FAILED'], true)) $la_status = '';
  if (!in_array($la_action, ['LOGIN', 'LOGOUT'], true))   $la_action = '';
  if ($la_date !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $la_date)) $la_date = '';

  $where = []; $params = []; $types = '';
  if ($la_search !== '') { $where[] = "username LIKE ?";        $params[] = "%{$la_search}%"; $types .= 's'; }
  if ($la_status !== '') { $where[] = "UPPER(status) = ?";      $params[] = $la_status;       $types .= 's'; }
  if ($la_action !== '') { $where[] = "UPPER(action) = ?";      $params[] = $la_action;       $types .= 's'; }
  if ($la_date   !== '') { $where[] = "DATE(timestamp) = ?";    $params[] = $la_date;         $types .= 's'; }
  $whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

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

  $perPage = 50;
  $pages   = max(1, (int)ceil($total / $perPage));
  $la_page = min(max(1, (int)($_GET['la_page'] ?? 1)), $pages);
  $offset  = ($la_page - 1) * $perPage;

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

  // Failed Login Report (failures grouped by username and by IP). Has its own period tabs (la_fp)
  // and does not use the search/status/date filters above.
  $flrThreshold = 5;
  $flrPeriods = [
      'day'   => ['Today',        'CURDATE()'],
      'week'  => ['Last 7 days',  'CURDATE() - INTERVAL 6 DAY'],
      'month' => ['Last 30 days', 'CURDATE() - INTERVAL 29 DAY'],
      'all'   => ['All time',     null],
  ];
  $la_fp = (string)($_GET['la_fp'] ?? 'week');
  if (!isset($flrPeriods[$la_fp])) $la_fp = 'week';
  $flrW = $flrPeriods[$la_fp][1] !== null ? " AND timestamp >= " . $flrPeriods[$la_fp][1] : "";

  function flrRows($conn, $sql) {
      $out = [];
      try {
          $q = $conn->query($sql);
          while ($q && $row = $q->fetch_assoc()) $out[] = $row;
      } catch (Throwable $e) { error_log('failed login report: ' . $e->getMessage()); }
      return $out;
  }

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

  function laPageUrl($n) {
      global $from;
      $q = $_GET; $q['la_page'] = $n; $q['from'] = $from; $q['tab'] = 'login';
      return '?' . http_build_query($q);
  }
}

/* =========================================================================
   SECURITY ACTIVITY TAB (prefixed sa_) — what admins/officers/personnel did:
   account changes, alumni updates, visitor registrations, announcements.
========================================================================= */
if ($tab === 'activity') {

  $sa_search = trim((string)($_GET['sa_search'] ?? ''));
  $sa_action = trim((string)($_GET['sa_action'] ?? ''));
  $sa_date   = trim((string)($_GET['sa_date'] ?? ''));
  $sa_search = function_exists('mb_substr') ? mb_substr($sa_search, 0, 60) : substr($sa_search, 0, 60);

  $saActions = [
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
  if ($sa_action !== '' && !isset($saActions[$sa_action])) $sa_action = '';
  if ($sa_date !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $sa_date)) $sa_date = '';

  $saWhere = []; $saParams = []; $saTypes = '';
  if ($sa_search !== '') {
    $saWhere[] = "(actor LIKE ? OR target LIKE ? OR details LIKE ?)";
    $like = '%' . addcslashes($sa_search, '%_') . '%';
    array_push($saParams, $like, $like, $like); $saTypes .= 'sss';
  }
  if ($sa_action !== '') { $saWhere[] = "action = ?";           $saParams[] = $sa_action; $saTypes .= 's'; }
  if ($sa_date   !== '') { $saWhere[] = "DATE(created_at) = ?"; $saParams[] = $sa_date;   $saTypes .= 's'; }
  $saWhereSQL = $saWhere ? 'WHERE ' . implode(' AND ', $saWhere) : '';

  $saTotal = $saToday = $saActors = 0;
  $saLast = '-';
  $saTableMissing = false;
  try {
    $r = $conn->query("SELECT COUNT(*) AS t,
                              COALESCE(SUM(DATE(created_at) = CURDATE()),0) AS d,
                              COUNT(DISTINCT actor) AS a,
                              MAX(created_at) AS l
                       FROM (SELECT id, actor_name_snapshot AS actor, actor_role, action, target_label AS target, details, ip_address, logged_at AS created_at FROM activity_logs) activity_logs")->fetch_assoc();
    $saTotal = (int)$r['t']; $saToday = (int)$r['d']; $saActors = (int)$r['a'];
    if ($r['l']) $saLast = date('M j, g:i A', strtotime($r['l']));
  } catch (Throwable $e) {
    $saTableMissing = true;
    error_log('activity cards: ' . $e->getMessage());
  }

  $saRowTotal = 0;
  $saRows = [];
  if (!$saTableMissing) {
    try {
      $q = $conn->prepare("SELECT COUNT(*) FROM (SELECT id, actor_name_snapshot AS actor, actor_role, action, target_label AS target, details, ip_address, logged_at AS created_at FROM activity_logs) activity_logs $saWhereSQL");
      if ($saParams) $q->bind_param($saTypes, ...$saParams);
      $q->execute();
      $q->bind_result($saRowTotal);
      $q->fetch();
      $q->close();
    } catch (Throwable $e) { error_log('activity count: ' . $e->getMessage()); }
  }
  $saPerPage = 50;
  $saPages   = max(1, (int)ceil($saRowTotal / $saPerPage));
  $sa_page   = min(max(1, (int)($_GET['sa_page'] ?? 1)), $saPages);
  $saOffset  = ($sa_page - 1) * $saPerPage;

  if (!$saTableMissing) {
    try {
      $q = $conn->prepare("SELECT actor, actor_role, action, target, details, ip_address, created_at
                           FROM (SELECT id, actor_name_snapshot AS actor, actor_role, action, target_label AS target, details, ip_address, logged_at AS created_at FROM activity_logs) activity_logs $saWhereSQL ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?");
      $t2 = $saTypes . 'ii'; $p2 = array_merge($saParams, [$saPerPage, $saOffset]);
      $q->bind_param($t2, ...$p2);
      $q->execute();
      $res = $q->get_result();
      while ($row = $res->fetch_assoc()) $saRows[] = $row;
      $q->close();
    } catch (Throwable $e) { error_log('activity rows: ' . $e->getMessage()); }
  }

  function saPageUrl($n) {
    global $from;
    $q = $_GET; $q['sa_page'] = $n; $q['from'] = $from; $q['tab'] = 'activity';
    return '?' . http_build_query($q);
  }

  function actionClass($a) {
    if ($a === 'DELETE ACCOUNT' || $a === 'DEACTIVATE ACCOUNT') return 'b-red';
    if ($a === 'RESET PASSWORD') return 'b-amber';
    if ($a === 'CREATE ACCOUNT' || $a === 'ACTIVATE ACCOUNT' || $a === 'REGISTER VISITOR') return 'b-green';
    return 'b-blue';
  }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Activity Logs</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root { --ink: #16233d; --navy: #1c3a5e; --line: #dce4ef; --muted: #8a9bb5; --gold: #f0b429; --gold-soft: #fffdf5; --gold-glow: 0 8px 24px rgba(240,180,41,0.25); }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fafbfd; min-height: 100vh; display: flex; color: var(--ink); }
svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.sidebar { width: 220px; flex-shrink: 0; background: linear-gradient(180deg, #1c3a5e, #0f2440); border-right: 1px solid #0f2440; height: 100vh; position: sticky; top: 0; display: flex; flex-direction: column; align-items: stretch; padding: 24px 18px; gap: 12px; overflow-y: auto; }
.sidebar .logo { display: flex; flex-direction: column; align-items: center; gap: 10px; text-align: center; }
.sidebar .logo-text { display: flex; flex-direction: column; gap: 2px; }
.sidebar .logo-univ { font-size: 12px; font-weight: 700; line-height: 1.3; color: #fff; }
.sidebar .logo-campus { font-size: 11px; font-weight: 500; color: rgba(255,255,255,0.6); }
.sidebar .logo img { width: 44px; height: 44px; border-radius: 50%; object-fit: cover; }
.sidebar-divider { width: 100%; height: 1px; background: rgba(255,255,255,0.12); margin: 4px 0; }
.sidebar .nav-item { display: flex; align-items: center; gap: 14px; width: 100%; color: #fff; text-decoration: none; font-size: 14px; font-weight: 500; white-space: nowrap; position: relative; }
.sidebar .nav-icon { width: 44px; height: 44px; border-radius: 12px; flex-shrink: 0; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12); display: flex; align-items: center; justify-content: center; transition: background .2s, border-color .2s, transform .2s; }
.sidebar .nav-icon svg { width: 20px; height: 20px; }
.sidebar .nav-label { color: rgba(255,255,255,0.85); overflow: hidden; text-overflow: ellipsis; }
.sidebar .nav-item:hover .nav-icon { background: rgba(240,180,41,0.18); border-color: var(--gold); transform: translateY(-1px); }
.sidebar .nav-item.active .nav-icon { background: rgba(240,180,41,0.25); border-color: var(--gold); }
.sidebar .nav-item.active .nav-label { color: #fff; font-weight: 600; }
.sidebar .user-divider { margin-top: auto; }
.sidebar-user { display: flex; align-items: center; gap: 12px; width: 100%; padding: 4px 0; }
.su-avatar { width: 40px; height: 40px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; background: rgba(169,196,232,0.15); border: 1px solid rgba(169,196,232,0.35); color: #a9c4e8; font-size: 15px; font-weight: 700; }
.su-text { display: flex; flex-direction: column; min-width: 0; }
.su-name { font-size: 13px; font-weight: 600; color: #a9c4e8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.su-label { font-size: 10px; font-style: italic; color: rgba(169,196,232,0.6); margin-top: 1px; }
.sidebar .logout-item { margin-top: 0; }
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

/* ---- Toolbar: underline tabs + Filters button, filter panel folds out underneath ---- */
.toolbar { background: #fff; border: 1px solid var(--line); border-radius: 16px; box-shadow: 0 1px 3px rgba(22,58,94,0.05); margin-bottom: 16px; overflow: hidden; }
.toolbar-row { display: flex; align-items: stretch; justify-content: space-between; gap: 16px; flex-wrap: wrap; padding: 0 24px; }
.utabs { display: flex; gap: 28px; }
.utab { display: flex; align-items: center; padding: 18px 2px; font-size: 15px; font-weight: 600; color: var(--muted); text-decoration: none; border-bottom: 2px solid transparent; transition: color .15s, border-color .15s; }
.utab:hover { color: var(--ink); }
.utab.active { color: var(--navy); border-bottom-color: var(--gold); }
.utab:focus-visible { outline: 2px solid var(--gold); outline-offset: -2px; border-radius: 6px; }
.toolbar-right { display: flex; align-items: center; gap: 12px; padding: 10px 0; flex-wrap: wrap; }
.btn-filters { padding: 9px 16px; }
.btn-filters[aria-expanded="true"] { background: var(--gold-soft); border-color: var(--gold); }
.fcount { min-width: 18px; height: 18px; padding: 0 5px; border-radius: 9px; background: var(--gold); color: var(--ink); font-size: 11px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center; }
.filters.filters-panel { margin: 0; border: 0; border-top: 1px solid var(--line); border-radius: 0; background: #fafbfd; padding: 16px 24px; }
.filters.filters-panel[hidden] { display: none; }

/* ---- Segmented control (period picker) ---- */
.seg { display: inline-flex; flex-wrap: wrap; gap: 2px; padding: 4px; background: #f4f7fb; border: 1px solid var(--line); border-radius: 12px; }
.seg-btn { padding: 8px 18px; border-radius: 9px; font-size: 13px; font-weight: 600; color: #6b7a94; text-decoration: none; transition: background .15s, color .15s; }
.seg-btn:hover { color: var(--ink); background: var(--gold-soft); }
.seg-btn.active { background: var(--navy); color: #fff; }
.seg-btn:focus-visible { outline: 2px solid var(--gold); outline-offset: 1px; }
.cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
.card { flex: 1; min-width: 150px; background: #fff; padding: 20px; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); transition: border-color .2s, box-shadow .2s; }
.card:hover { border-color: var(--gold); box-shadow: var(--gold-glow); }
.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.card h2 { font-size: 30px; margin-top: 8px; color: var(--navy); }
.card h2.small { font-size: 16px; margin-top: 14px; }
.filters { background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 18px; margin-bottom: 20px; display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.filter-group { display: flex; flex-direction: column; gap: 6px; }
.filter-group.grow { flex: 1; min-width: 200px; }
.filter-group label { font-size: 11px; color: var(--muted); font-weight: 600; text-transform: uppercase; }
input, select { height: 40px; padding: 0 12px; border: 1px solid var(--line); border-radius: 9px; background: #fff; color: var(--ink); font-size: 13px; outline: none; font-family: inherit; }
.filter-group.grow input { width: 100%; }
input:focus, select:focus { border-color: var(--gold); box-shadow: 0 0 0 3px rgba(240,180,41,.12); }
.section { background: #fff; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px; }
.section h3 { font-size: 14px; margin-bottom: 18px; }
.section .hint { font-size: 12px; color: var(--muted); margin-bottom: 14px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: .06em; padding: 0 12px 12px 0; white-space: nowrap; }
td { padding: 12px 12px 12px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; vertical-align: top; }
td small { display: block; font-size: 11px; color: var(--muted); margin-top: 2px; }
.badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
.badge-success, .b-green { background: #e8f8ef; color: #16a34a; }
.badge-failed, .b-red { background: #fdeaea; color: #dc2626; }
.badge-action, .b-blue { background: #eef3fa; color: var(--navy); }
.badge-warn, .b-amber { background: #fff4db; color: #b45309; margin-left: 4px; }
.empty { color: #b7c3d6; text-align: center; padding: 30px; }
.notice { background: #fff4db; border: 1px solid #f6d58a; color: #7a4b05; border-radius: 12px; padding: 12px 16px; font-size: 13px; margin-bottom: 16px; }
.pager { display: flex; justify-content: space-between; align-items: center; margin-top: 18px; font-size: 13px; color: var(--muted); gap: 12px; flex-wrap: wrap; }
.pager .btn[aria-disabled="true"] { opacity: .4; pointer-events: none; }

/* Failed Login Report */
.report { margin-bottom: 20px; }
.report h3 { margin-bottom: 4px; }
.report .hint { font-size: 12px; color: var(--muted); margin-bottom: 14px; }
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

@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .sidebar .logo-text { display: none; }
  .su-text { display: none; }
  .sidebar-user { justify-content: center; }
  .main { padding: 20px; }
  .cards { flex-direction: column; }
  .report-grid { flex-direction: column; }
  .toolbar-row { padding: 0 16px; }
  .filters.filters-panel { padding: 16px; }
}
@media (prefers-reduced-motion: reduce) { .btn, .card, .sidebar .nav-icon, .utab, .seg-btn { transition: none; } }
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
  <a class="nav-item" href="<?= h($nav['dash']) ?>" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="<?= h($nav['users']) ?>" data-tip="Users" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item" href="<?= h($nav['sec']) ?>" data-tip="Security Accounts" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
  <a class="nav-item" href="<?= h($nav['logs']) ?>" data-tip="Access Logs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item" href="security_summary.php?from=<?= h($from) ?>" data-tip="Security Overview" aria-label="Security Overview"><span class="nav-icon"><?= icon('chart') ?></span><span class="nav-label">Security Overview</span></a>
  <a class="nav-item active" href="authentication_logs.php?from=<?= h($from) ?>" data-tip="Activity Logs" aria-label="Activity Logs" aria-current="page"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Activity Logs</span></a>
  <div class="sidebar-divider user-divider"></div>
  <div class="sidebar-user" title="<?= htmlspecialchars($loggedName) ?>">
    <span class="su-avatar"><?= htmlspecialchars(strtoupper(substr($loggedName, 0, 1))) ?></span>
    <span class="su-text">
      <span class="su-name"><?= htmlspecialchars($loggedName) ?></span>
      <span class="su-label">Logged in</span>
    </span>
  </div>
  <a class="nav-item logout-item" href="<?= h($nav['logout']) ?>" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<main class="main">

  <div class="header">
    <div class="header-left">
      <h1>Activity Logs</h1>
      <p><?= $tab === 'login' ? 'Who signed in and out, and failed attempts' : 'What administrators, officers and personnel did: account changes, alumni updates and visitor registrations' ?></p>
    </div>
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <div class="admin-badge">Logged in as <span class="role"><?= h($nav['label']) ?></span></div>
      <a href="<?= h($nav['dash']) ?>" class="btn">Back to Dashboard</a>
    </div>
  </div>

  <?php
    $filterCount = $tab === 'login'
      ? ($la_search !== '') + ($la_action !== '') + ($la_status !== '') + ($la_date !== '')
      : ($sa_search !== '') + ($sa_action !== '') + ($sa_date !== '');
  ?>
  <div class="toolbar">
    <div class="toolbar-row">
      <nav class="utabs" aria-label="Sections">
        <a class="utab <?= $tab === 'login' ? 'active' : '' ?>" href="?tab=login&amp;from=<?= h($from) ?>" <?= $tab === 'login' ? 'aria-current="page"' : '' ?>>Login Activity</a>
        <a class="utab <?= $tab === 'activity' ? 'active' : '' ?>" href="?tab=activity&amp;from=<?= h($from) ?>" <?= $tab === 'activity' ? 'aria-current="page"' : '' ?>>Security Activity</a>
      </nav>
      <div class="toolbar-right">
        <?php if ($tab === 'login'): ?>
        <div class="seg" role="group" aria-label="Failed Login Report period">
          <?php foreach ($flrPeriods as $key => $info): ?>
            <?php $tq = $_GET; unset($tq['la_page']); $tq['la_fp'] = $key; $tq['from'] = $from; $tq['tab'] = 'login'; ?>
            <a class="seg-btn <?= $key === $la_fp ? 'active' : '' ?>" href="?<?= h(http_build_query($tq)) ?>" <?= $key === $la_fp ? 'aria-current="true"' : '' ?>><?= h($info[0]) ?></a>
          <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <button type="button" class="btn btn-filters" id="filtersBtn" aria-expanded="<?= $filterCount ? 'true' : 'false' ?>" aria-controls="filtersPanel">
          <?= icon('filter') ?>Filters<?php if ($filterCount): ?><span class="fcount"><?= (int)$filterCount ?></span><?php endif; ?>
        </button>
      </div>
    </div>

    <?php if ($tab === 'login'): ?>
    <form method="GET" class="filters filters-panel" id="filtersPanel" <?= $filterCount ? '' : 'hidden' ?>>
      <input type="hidden" name="from" value="<?= h($from) ?>">
      <input type="hidden" name="tab" value="login">
      <input type="hidden" name="la_fp" value="<?= h($la_fp) ?>">
      <div class="filter-group">
        <label for="la_search">Search Username</label>
        <input type="text" id="la_search" name="la_search" placeholder="Enter username..." value="<?= h($la_search) ?>">
      </div>
      <div class="filter-group">
        <label for="la_action">Activity</label>
        <select id="la_action" name="la_action">
          <option value="">All Activity</option>
          <option value="LOGIN"  <?= $la_action === 'LOGIN'  ? 'selected' : '' ?>>Login</option>
          <option value="LOGOUT" <?= $la_action === 'LOGOUT' ? 'selected' : '' ?>>Logout</option>
        </select>
      </div>
      <div class="filter-group">
        <label for="la_status">Status</label>
        <select id="la_status" name="la_status">
          <option value="">All Status</option>
          <option value="SUCCESS" <?= $la_status === 'SUCCESS' ? 'selected' : '' ?>>Success</option>
          <option value="FAILED"  <?= $la_status === 'FAILED'  ? 'selected' : '' ?>>Failed</option>
        </select>
      </div>
      <div class="filter-group">
        <label for="la_date">Date</label>
        <input type="date" id="la_date" name="la_date" value="<?= h($la_date) ?>">
      </div>
      <button type="submit" class="btn btn-primary"><?= icon('search') ?> Filter</button>
      <a href="authentication_logs.php?from=<?= h($from) ?>&amp;tab=login" class="btn">Clear</a>
    </form>
    <?php else: ?>
    <form method="GET" class="filters filters-panel" id="filtersPanel" <?= $filterCount ? '' : 'hidden' ?>>
      <input type="hidden" name="from" value="<?= h($from) ?>">
      <input type="hidden" name="tab" value="activity">
      <div class="filter-group grow">
        <label for="sa_search">Search</label>
        <input type="text" id="sa_search" name="sa_search" maxlength="60" placeholder="Who did it, or who it was done to..." value="<?= h($sa_search) ?>">
      </div>
      <div class="filter-group">
        <label for="sa_action">Action</label>
        <select id="sa_action" name="sa_action">
          <option value="">All actions</option>
          <?php foreach ($saActions as $k => $label): ?>
            <option value="<?= h($k) ?>" <?= $sa_action === $k ? 'selected' : '' ?>><?= h($label) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="filter-group">
        <label for="sa_date">Date</label>
        <input type="date" id="sa_date" name="sa_date" value="<?= h($sa_date) ?>">
      </div>
      <button type="submit" class="btn btn-primary"><?= icon('search') ?> Filter</button>
      <a href="authentication_logs.php?from=<?= h($from) ?>&amp;tab=activity" class="btn">Clear</a>
    </form>
    <?php endif; ?>
  </div>

  <?php if ($tab === 'login'): ?>

  <div class="cards">
    <div class="card"><small>Total Records</small><h2><?= $total ?></h2></div>
    <div class="card"><small>Successful</small><h2><?= $successful ?></h2></div>
    <div class="card"><small>Failed</small><h2><?= $failed ?></h2></div>
  </div>

  <div class="section report" id="failed-login-report">
    <h3>Failed Login Report</h3>
    <p class="hint"><?= h($flrPeriods[$la_fp][0]) ?> · wrong username or password attempts, grouped. Click a username to see its failed attempts below.</p>

    <?php if (!$flrIp): ?>
      <div class="notice"><strong>IP grouping is off.</strong> No IP column was found in <code>auth_logs</code>, so only the by-username report works.</div>
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
                    <a class="user" href="?<?= h(http_build_query(['la_search' => $r['username'], 'la_status' => 'FAILED', 'from' => $from, 'tab' => 'login'])) ?>"><?= h($r['username']) ?></a>
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
              <tr><td colspan="4" class="report-empty">No IP column in auth_logs</td></tr>
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
      <span>Page <?= $la_page ?> of <?= $pages ?> · <?= $total ?> records</span>
      <span style="display:flex;gap:8px">
        <a class="btn" href="<?= h(laPageUrl($la_page - 1)) ?>" <?= $la_page <= 1 ? 'aria-disabled="true"' : '' ?>>Previous</a>
        <a class="btn" href="<?= h(laPageUrl($la_page + 1)) ?>" <?= $la_page >= $pages ? 'aria-disabled="true"' : '' ?>>Next</a>
      </span>
    </div>
  </div>

  <?php else /* $tab === 'activity' */: ?>

  <?php if ($saTableMissing): ?>
    <div class="notice"><strong>The activity table does not exist yet.</strong> Run <code>activity_logs_database.sql</code> once in phpMyAdmin, then reload this page.</div>
  <?php endif; ?>

  <div class="cards">
    <div class="card"><small>Total actions</small><h2><?= $saTotal ?></h2></div>
    <div class="card"><small>Today</small><h2><?= $saToday ?></h2></div>
    <div class="card"><small>People who acted</small><h2><?= $saActors ?></h2></div>
    <div class="card"><small>Latest action</small><h2 class="small"><?= h($saLast) ?></h2></div>
  </div>


  <div class="section">
    <h3>All Recorded Actions</h3>
    <p class="hint">Newest first. Login and logout are in the Login Activity tab, not here.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>#</th><th>Date &amp; Time</th><th>Done by</th><th>Action</th><th>Done to</th><th>IP address</th></tr></thead>
        <tbody>
        <?php if ($saRows): foreach ($saRows as $i => $row): ?>
          <tr>
            <td><?= $saOffset + $i + 1 ?></td>
            <td><?= h(date('M j, Y, g:i A', strtotime($row['created_at']))) ?></td>
            <td><strong><?= h($row['actor']) ?></strong><small><?= h($row['actor_role']) ?></small></td>
            <td><span class="badge <?= actionClass($row['action']) ?>"><?= h($saActions[$row['action']] ?? $row['action']) ?></span></td>
            <td><?= $row['target'] !== null && $row['target'] !== '' ? h($row['target']) : '-' ?><?php if (!empty($row['details'])): ?><small><?= h($row['details']) ?></small><?php endif; ?></td>
            <td><?= h($row['ip_address'] ?: '-') ?></td>
          </tr>
        <?php endforeach; else: ?>
          <tr><td colspan="6" class="empty"><?= $saTableMissing ? 'Activity table not created yet.' : 'No activity recorded yet.' ?></td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>

    <div class="pager">
      <span>Page <?= $sa_page ?> of <?= $saPages ?> · <?= $saRowTotal ?> records</span>
      <span style="display:flex;gap:8px">
        <a class="btn" href="<?= h(saPageUrl($sa_page - 1)) ?>" <?= $sa_page <= 1 ? 'aria-disabled="true"' : '' ?>>Previous</a>
        <a class="btn" href="<?= h(saPageUrl($sa_page + 1)) ?>" <?= $sa_page >= $saPages ? 'aria-disabled="true"' : '' ?>>Next</a>
      </span>
    </div>
  </div>

  <?php endif; ?>

</main>

<script>
// Filters button: show / hide the filter panel
(function () {
  var btn = document.getElementById('filtersBtn'), panel = document.getElementById('filtersPanel');
  if (!btn || !panel) return;
  btn.addEventListener('click', function () {
    var open = panel.hasAttribute('hidden');
    if (open) panel.removeAttribute('hidden'); else panel.setAttribute('hidden', '');
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) { var f = panel.querySelector('input:not([type=hidden]), select'); if (f) f.focus(); }
  });
})();
</script>
</body>
</html>