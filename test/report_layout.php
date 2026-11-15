<?php
// Shared layout for the report pages (failed_logins.php).
// Same look and same admin/officer "from" handling as security_summary.php.

if (!function_exists('h')) {
  function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
}

function report_guard() {
  if (empty($_SESSION['admin_logged_in']) && empty($_SESSION['officer_logged_in'])) {
    header("Location: login.php");
    exit;
  }
  header("Cache-Control: no-cache, no-store, must-revalidate");
}

function report_context() {
  $backMap = ['admin' => 'admin_dashboard.php', 'officer' => 'officer_dashboard.php'];
  $from = $_GET['from'] ?? '';
  $loggedIn = ['admin' => !empty($_SESSION['admin_logged_in']), 'officer' => !empty($_SESSION['officer_logged_in'])];
  if (isset($loggedIn[$from]) && $loggedIn[$from]) {
    // the link says which role is using the page: trust it (only if that role is really logged in)
    $_SESSION['summary_from'] = $from;
  } else {
    $from = $_SESSION['summary_from'] ?? '';
    if (!isset($loggedIn[$from]) || !$loggedIn[$from]) {
      // no usable hint: use the role that logged in most recently
      $last = $_SESSION['last_role'] ?? '';
      $from = (isset($loggedIn[$last]) && $loggedIn[$last]) ? $last : ($loggedIn['admin'] ? 'admin' : 'officer');
    }
  }
  $navMap = [
    'admin'   => ['dash' => 'admin_dashboard.php',   'users' => 'users.php',         'sec' => 'manage_security.php',  'logs' => 'admin_logs.php',   'logout' => 'admin_logout.php',   'label' => 'Administrator'],
    'officer' => ['dash' => 'officer_dashboard.php', 'users' => 'officer_users.php', 'sec' => 'officer_security.php', 'logs' => 'officer_logs.php', 'logout' => 'officer_logout.php', 'label' => 'Security Officer'],
  ];
  return ['from' => $from, 'nav' => $navMap[$from]];
}

function report_icon($name) {
  $paths = [
    'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'chart'  => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    'logout' => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    'alert'  => '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5h.01"/>',
    'shield' => '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  ];
  return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}

/** Prints everything from <!DOCTYPE> to the opening of the page header. */
function report_start($title, $subtitle, $active) {
  $ctx = report_context();
  $from = $ctx['from'];
  $nav = $ctx['nav'];
  $items = [
    ['dash',   $nav['dash'],                                  'Dashboard',            'home'],
    ['users',  $nav['users'],                                 'Users',                'user'],
    ['sec',    $nav['sec'],                                   'Security Accounts',    'lock'],
    ['logs',   $nav['logs'],                                  'Logs',                 'list'],
    ['summary','security_summary.php?from=' . $from,          'Security Summary',     'chart'],
    ['failed', 'failed_logins.php?from=' . $from,             'Failed Login Report',  'shield'],
    ['auth',   'authentication_logs.php?from=' . $from,       'Login Activity',       'list'],
  ];
  ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($title) ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root { --ink: #16233d; --navy: #1c3a5e; --line: #dce4ef; --muted: #8a9bb5; --gold: #f0b429; --gold-soft: #fffdf5; --gold-glow: 0 8px 24px rgba(240,180,41,0.25); }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fafbfd; min-height: 100vh; display: flex; color: var(--ink); }
svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.sidebar { width: 220px; flex-shrink: 0; background: linear-gradient(180deg, #1c3a5e, #0f2440); height: 100vh; position: sticky; top: 0; display: flex; flex-direction: column; padding: 24px 18px; gap: 12px; overflow-y: auto; }
.sidebar .logo { display: flex; justify-content: center; }
.sidebar .logo img { width: 44px; height: 44px; border-radius: 12px; object-fit: cover; }
.sidebar-divider { width: 100%; height: 1px; background: rgba(255,255,255,0.12); margin: 4px 0; }
.sidebar .nav-item { display: flex; align-items: center; gap: 14px; width: 100%; color: #fff; text-decoration: none; font-size: 14px; font-weight: 500; white-space: nowrap; }
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
.header-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.admin-badge { font-size: 12px; color: #6b7a94; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--line); background: #fff; }
.admin-badge .role { color: #d97706; font-weight: 600; }
.btn { display: inline-block; text-decoration: none; border-radius: 12px; border: 1px solid var(--line); background: #fff; color: var(--ink); font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; padding: 11px 20px; transition: transform .15s, background .15s, border-color .15s, box-shadow .15s; }
.btn:hover { transform: translateY(-2px); background: var(--gold-soft); border-color: var(--gold); box-shadow: var(--gold-glow); }
.btn:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }
.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }
.btn-sm { padding: 8px 14px; }
.tabs { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #fff; padding: 20px; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); }
.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.card h2 { font-size: 32px; font-weight: 700; margin: 8px 0 4px; color: var(--navy); }
.sections { display: flex; gap: 16px; margin-bottom: 24px; align-items: flex-start; }
.section, .section-full { background: #fff; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px; }
.section { flex: 1; min-width: 0; }
.section-full { margin-bottom: 24px; }
.section h3, .section-full h3 { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.section .hint, .section-full .hint { font-size: 12px; color: var(--muted); margin-bottom: 14px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: 0.06em; padding: 0 12px 10px 0; white-space: nowrap; }
td { padding: 10px 12px 10px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; vertical-align: top; }
tr:hover td { color: var(--ink); }
td.r, th.r { text-align: right; }
td .sub { display: block; font-size: 11px; color: var(--muted); margin-top: 2px; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-security { background: #eef3fa; color: var(--navy); }
.badge-denied { background: #fdeaea; color: #dc2626; }
.badge-warn { background: #fff4db; color: #b45309; }
.badge-ok { background: #e8f8ef; color: #16a34a; }
.empty { color: #b7c3d6; font-size: 13px; padding: 12px 0; }
.notice { background: #fff4db; border: 1px solid #f6d58a; color: #7a4b05; border-radius: 12px; padding: 14px 16px; font-size: 13px; margin-bottom: 24px; line-height: 1.5; }
.notice code { background: rgba(0,0,0,0.06); padding: 1px 6px; border-radius: 6px; font-size: 12px; }
.filters { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 16px; }
.filters label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.filters select { font: inherit; font-size: 13px; color: var(--ink); padding: 9px 12px; border: 1px solid var(--line); border-radius: 10px; background: #fff; min-width: 160px; }
.pager { display: flex; gap: 8px; align-items: center; justify-content: space-between; margin-top: 14px; font-size: 12px; color: var(--muted); flex-wrap: wrap; }
.pager .links { display: flex; gap: 8px; }
.pager .off { opacity: .4; pointer-events: none; }
@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .main { padding: 20px; }
  .sections { flex-direction: column; }
}
@media (prefers-reduced-motion: reduce) { .btn, .sidebar .nav-icon { transition: none; } }
@media print { .sidebar, .no-print, .tabs, .filters, .pager .links { display: none !important; } .main { padding: 0; } body { background: #fff; } }
</style>
</head>
<body>
<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <?php foreach ($items as $it): ?>
    <a class="nav-item <?= $it[0] === $active ? 'active' : '' ?>" href="<?= h($it[1]) ?>" aria-label="<?= h($it[2]) ?>" <?= $it[0] === $active ? 'aria-current="page"' : '' ?>><span class="nav-icon"><?= report_icon($it[3]) ?></span><span class="nav-label"><?= h($it[2]) ?></span></a>
  <?php endforeach; ?>
  <a class="nav-item logout-item" href="<?= h($nav['logout']) ?>" aria-label="Logout"><span class="nav-icon"><?= report_icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>
<main class="main">
  <div class="header">
    <div class="header-left">
      <h1><?= h($title) ?></h1>
      <p><?= h($subtitle) ?> · <?= date('l, F j, Y') ?></p>
    </div>
    <div class="header-right no-print">
      <div class="admin-badge">Logged in as <span class="role"><?= h($nav['label']) ?></span></div>
      <button class="btn" type="button" onclick="window.print()">Print / Save as PDF</button>
    </div>
  </div>
<?php
}

function report_end() {
  echo "</main>\n</body>\n</html>";
}

/** Day / Week / Month / All time. Values are fixed SQL fragments, never user input. */
function report_periods() {
  return [
    'day'   => ['label' => 'Today',        'from' => 'CURDATE()'],
    'week'  => ['label' => 'Last 7 days',  'from' => 'CURDATE() - INTERVAL 6 DAY'],
    'month' => ['label' => 'Last 30 days', 'from' => 'CURDATE() - INTERVAL 29 DAY'],
    'all'   => ['label' => 'All time',     'from' => null],
  ];
}

function report_tabs($periods, $p, $extra = []) {
  echo '<div class="tabs no-print">';
  foreach ($periods as $key => $info) {
    $qs = http_build_query(array_merge($extra, ['p' => $key, 'from' => report_context()['from']]));
    echo '<a class="btn ' . ($key === $p ? 'btn-primary' : '') . '" href="?' . h($qs) . '">' . h($info['label']) . '</a>';
  }
  echo '</div>';
}

function report_rows($conn, $sql, $types = '', $params = []) {
  try {
    $st = $conn->prepare($sql);
    if (!$st) { error_log('report prepare: ' . $conn->error); return []; }
    if ($params) $st->bind_param($types, ...$params);
    $st->execute();
    $res = $st->get_result();
    return $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
  } catch (Throwable $e) {
    error_log('report rows: ' . $e->getMessage());
    return [];
  }
}

function report_columns($conn, $table) {
  $cols = [];
  try {
    $q = $conn->query("SHOW COLUMNS FROM `$table`");
    while ($q && $r = $q->fetch_assoc()) $cols[] = $r['Field'];
  } catch (Throwable $e) { error_log('report columns: ' . $e->getMessage()); }
  return $cols;
}