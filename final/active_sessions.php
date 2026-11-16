<?php
session_start();
include 'db.php';

// Only the administrator and the security officer can open this page
if (empty($_SESSION['admin_logged_in']) && empty($_SESSION['officer_logged_in'])) {
  header("Location: login.php");
  exit;
}

/* Which role is viewing? (one browser can hold both an admin and an officer login) */
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
$myKey = session_id() . '|' . ($from === 'admin' ? 'admin' : 'officer');   // my own row: I cannot force myself out

// Who can be force-logged-out by whom: admin -> officer + personnel, officer -> personnel only
// security_sessions stores roles in lowercase (admin / officer / personnel)
$canForce = $from === 'admin' ? ['officer', 'personnel'] : ['personnel'];

if (empty($_SESSION['csrf_sess'])) $_SESSION['csrf_sess'] = bin2hex(random_bytes(16));
$csrf = $_SESSION['csrf_sess'];

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function jsonOut($a, $code = 200) {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store');
  echo json_encode($a, JSON_UNESCAPED_UNICODE);
  exit;
}

/* ---------------- FORCE LOGOUT (POST) ---------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) jsonOut(['ok' => false, 'message' => 'Session expired. Reload the page.'], 403);
  $key = (string)($_POST['key'] ?? '');
  if ($key === '' || $key === $myKey) jsonOut(['ok' => false, 'message' => 'You cannot end your own session here. Use Logout.'], 400);

  try {
    $row = null;
    $q = $conn->prepare("SELECT username_snapshot AS username, role FROM security_sessions WHERE session_id = ? AND status = 'active'");
    $q->bind_param('s', $key);
    $q->execute();
    $row = $q->get_result()->fetch_assoc();
    $q->close();
    if (!$row) jsonOut(['ok' => false, 'message' => 'That session is no longer active.'], 404);
    if (!in_array($row['role'], $canForce, true)) jsonOut(['ok' => false, 'message' => 'You are not allowed to end this session.'], 403);

    $u = $conn->prepare("UPDATE security_sessions SET status = 'forced', logout_time = NOW() WHERE session_id = ? AND status = 'active'");
    $u->bind_param('s', $key);
    $u->execute();
    $u->close();

    // Leave a trace in the login/logout records (who was ended)
    try {
      $by  = $from === 'admin' ? ($_SESSION['admin_username'] ?? 'admin') : ($_SESSION['officer_username'] ?? 'officer');
      $ip  = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
      $act = 'FORCED LOGOUT';
      $sta = 'SUCCESS';
      $l = $conn->prepare("INSERT INTO auth_logs (username_snapshot, action, status, ip_address, logged_at) VALUES (?, ?, ?, ?, NOW())");
      $l->bind_param('ssss', $row['username'], $act, $sta, $ip);
      $l->execute();
      $l->close();
    } catch (Throwable $e) { error_log('force logout log: ' . $e->getMessage()); }

    jsonOut(['ok' => true, 'message' => $row['username'] . ' was logged out.']);
  } catch (Throwable $e) {
    error_log('force logout: ' . $e->getMessage());
    jsonOut(['ok' => false, 'message' => 'Could not end the session.'], 500);
  }
}

/* ---------------- LIVE FEED (GET ?feed=1) ---------------- */
if (isset($_GET['feed'])) {
  try {
    // Logins that stopped answering (tab closed, computer off) are marked timed out after 15 minutes
    $conn->query("UPDATE security_sessions SET status = 'timed_out', logout_time = last_activity
                  WHERE status = 'active' AND last_activity < NOW() - INTERVAL 15 MINUTE");

    $active = [];
    $r = $conn->query("SELECT session_id, username_snapshot AS username, role, ip_address, login_time, last_activity,
                              TIMESTAMPDIFF(SECOND, last_activity, NOW()) AS idle_s
                       FROM security_sessions WHERE status = 'active' ORDER BY login_time DESC");
    while ($r && $row = $r->fetch_assoc()) {
      $active[] = [
        'key'      => $row['session_id'],
        'username' => $row['username'],
        'role'     => $row['role'],
        'ip'       => $row['ip_address'] ?: '-',
        'login'    => date('M j, g:i A', strtotime($row['login_time'])),
        'last'     => date('g:i:s A', strtotime($row['last_activity'])),
        'idle_s'   => max(0, (int)$row['idle_s']),
        'me'       => $row['session_id'] === $myKey,
        'can'      => in_array($row['role'], $canForce, true) && $row['session_id'] !== $myKey,
      ];
    }

    $hist = [];
    $r = $conn->query("SELECT username_snapshot AS username, role, ip_address, login_time, logout_time, status
                       FROM security_sessions WHERE status <> 'active'
                       ORDER BY COALESCE(logout_time, login_time) DESC LIMIT 15");
    while ($r && $row = $r->fetch_assoc()) {
      $hist[] = [
        'username' => $row['username'],
        'role'     => $row['role'],
        'ip'       => $row['ip_address'] ?: '-',
        'login'    => date('M j, g:i A', strtotime($row['login_time'])),
        'logout'   => $row['logout_time'] ? date('M j, g:i A', strtotime($row['logout_time'])) : '-',
        'status'   => $row['status'],
      ];
    }
    jsonOut(['ok' => true, 'active' => $active, 'history' => $hist]);
  } catch (Throwable $e) {
    error_log('sessions feed: ' . $e->getMessage());
    jsonOut(['ok' => false, 'message' => 'Could not load sessions.'], 500);
  }
}

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
<title>Active Sessions</title>
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
.live { display: inline-flex; align-items: center; gap: 7px; background: #fff; border: 1px solid var(--line); border-radius: 10px; padding: 7px 12px; font-size: 12px; color: #16a34a; font-weight: 600; }
.live i { width: 8px; height: 8px; border-radius: 50%; background: #16a34a; box-shadow: 0 0 0 4px rgba(22,163,74,0.12); }
.live.off { color: #dc2626; } .live.off i { background: #dc2626; box-shadow: 0 0 0 4px rgba(220,38,38,0.12); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #fff; padding: 18px 20px; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); }
.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.card h2 { font-size: 30px; margin-top: 6px; color: var(--navy); font-variant-numeric: tabular-nums; }
.section { background: #fff; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px; margin-bottom: 24px; }
.section h3 { font-size: 14px; margin-bottom: 4px; }
.section .hint { font-size: 12px; color: var(--muted); margin-bottom: 14px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: .06em; padding: 0 12px 10px 0; white-space: nowrap; }
td { padding: 11px 12px 11px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; vertical-align: middle; }
td.r, th.r { text-align: right; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.b-role { background: #eef3fa; color: var(--navy); }
.b-on { background: #e8f8ef; color: #16a34a; }
.b-idle { background: #fff4db; color: #b45309; }
.b-out { background: #eef2f8; color: #6b7a94; }
.b-forced { background: #fdeaea; color: #dc2626; }
.me { font-size: 11px; color: var(--muted); margin-left: 6px; }
.btn { display: inline-block; border-radius: 10px; border: 1px solid #f0b4b4; background: #fff; color: #b91c1c; font-size: 12px; font-weight: 600; font-family: inherit; cursor: pointer; padding: 7px 14px; transition: background .15s; }
.btn:hover { background: #fdeaea; }
.btn:disabled { opacity: .5; cursor: default; }
.empty { color: #b7c3d6; padding: 18px 0; font-size: 13px; text-align: center; }
.toast { position: fixed; right: 20px; bottom: 20px; background: var(--ink); color: #fff; padding: 11px 16px; border-radius: 10px; font-size: 13px; display: none; z-index: 50; }
.modal { position: fixed; inset: 0; background: rgba(22,35,61,.55); display: none; align-items: center; justify-content: center; z-index: 60; padding: 16px; }
.modal.show { display: flex; }
.modal-box { background: #fff; border-radius: 16px; padding: 24px; max-width: 380px; width: 100%; }
.modal-box h4 { font-size: 16px; margin-bottom: 8px; }
.modal-box p { font-size: 13px; color: #6b7a94; margin-bottom: 18px; line-height: 1.5; }
.modal-actions { display: flex; gap: 10px; justify-content: flex-end; }
.modal-actions button { border-radius: 10px; border: 1px solid var(--line); background: #fff; color: var(--ink); font-size: 13px; font-weight: 600; font-family: inherit; cursor: pointer; padding: 9px 16px; }
.modal-actions .danger { background: #b91c1c; border-color: #b91c1c; color: #fff; }
@media (max-width: 860px) { .sidebar { width: 64px; padding: 24px 10px; } .sidebar .nav-label { display: none; } .main { padding: 20px; } }
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
  <a class="nav-item" href="authentication_logs.php?from=<?= h($from) ?>" data-tip="Login Activity" aria-label="Login Activity"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Login Activity</span></a>
  <a class="nav-item" href="activity_logs.php" data-tip="Security Activity" aria-label="Security Activity"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Security Activity</span></a>
  <a class="nav-item active" href="active_sessions.php?from=<?= h($from) ?>" data-tip="Active Sessions" aria-label="Active Sessions" aria-current="page"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Active Sessions</span></a>
  <a class="nav-item logout-item" href="<?= h($nav['logout']) ?>" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<main class="main">
  <div class="header">
    <div class="header-left">
      <h1>Active Sessions</h1>
      <p>Who is logged in right now. Updates every 5 seconds.</p>
    </div>
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <span class="live" id="live"><i></i><span id="liveText">LIVE</span></span>
      <div class="admin-badge">Logged in as <span class="role"><?= h($nav['label']) ?></span></div>
    </div>
  </div>

  <div class="cards">
    <div class="card"><small>Logged in now</small><h2 id="cTotal">0</h2></div>
    <div class="card"><small>Administrators</small><h2 id="cAdmin">0</h2></div>
    <div class="card"><small>Security officers</small><h2 id="cOfficer">0</h2></div>
    <div class="card"><small>Security personnel</small><h2 id="cPers">0</h2></div>
  </div>

  <div class="section">
    <h3>Currently logged in</h3>
    <p class="hint"><?= $from === 'admin' ? 'You can end the session of any security officer or personnel.' : 'You can end the session of security personnel.' ?> "Idle" means no activity for 2 minutes or more (for example a closed tab).</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>IP address</th><th>Logged in</th><th>Last activity</th><th>State</th><th class="r">Action</th></tr></thead>
        <tbody id="activeBody"><tr><td colspan="7" class="empty">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h3>Recent sessions that ended</h3>
    <p class="hint">Logged out, timed out (no activity for 15 minutes), or ended by an administrator or officer.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>IP address</th><th>Logged in</th><th>Ended</th><th>How</th></tr></thead>
        <tbody id="histBody"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>
</main>

<div class="modal" id="modal" role="dialog" aria-modal="true" aria-labelledby="mTitle">
  <div class="modal-box">
    <h4 id="mTitle">End this session?</h4>
    <p id="mText"></p>
    <div class="modal-actions">
      <button type="button" id="mCancel">Cancel</button>
      <button type="button" class="danger" id="mOk">Log out</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const $ = id => document.getElementById(id);
let pendingKey = null, pendingName = '';

function cell(tr, text, cls) {
  const td = tr.insertCell();
  if (cls) td.className = cls;
  td.textContent = text;
  return td;
}
function pill(text, cls) {
  const s = document.createElement('span');
  s.className = 'badge ' + cls;
  s.textContent = text;
  return s;
}
function emptyRow(body, cols, text) {
  body.textContent = '';
  const td = body.insertRow().insertCell();
  td.colSpan = cols; td.className = 'empty'; td.textContent = text;
}
function toast(msg) {
  const t = $('toast');
  t.textContent = msg; t.style.display = 'block';
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => t.style.display = 'none', 4000);
}

function render(d) {
  const a = d.active, count = r => a.filter(x => x.role === r).length;
  $('cTotal').textContent = a.length;
  $('cAdmin').textContent = count('Administrator');
  $('cOfficer').textContent = count('Security Officer');
  $('cPers').textContent = count('Security Personnel');

  const body = $('activeBody');
  if (!a.length) emptyRow(body, 7, 'Nobody is logged in');
  else {
    body.textContent = '';
    a.forEach(s => {
      const tr = body.insertRow();
      const u = cell(tr, s.username);
      u.style.fontWeight = '600';
      if (s.me) { const m = document.createElement('span'); m.className = 'me'; m.textContent = '(you)'; u.appendChild(m); }
      cell(tr, '').appendChild(pill(s.role, 'b-role'));
      cell(tr, s.ip);
      cell(tr, s.login);
      cell(tr, s.last);
      const idle = s.idle_s >= 120;
      cell(tr, '').appendChild(pill(idle ? 'Idle' : 'Online', idle ? 'b-idle' : 'b-on'));
      const act = cell(tr, '', 'r');
      if (s.can) {
        const b = document.createElement('button');
        b.type = 'button'; b.className = 'btn'; b.textContent = 'Force logout';
        b.addEventListener('click', () => ask(s.key, s.username));
        act.appendChild(b);
      } else act.textContent = '-';
    });
  }

  const hb = $('histBody');
  if (!d.history.length) emptyRow(hb, 6, 'No ended sessions yet');
  else {
    hb.textContent = '';
    d.history.forEach(s => {
      const tr = hb.insertRow();
      cell(tr, s.username).style.fontWeight = '600';
      cell(tr, '').appendChild(pill(s.role, 'b-role'));
      cell(tr, s.ip);
      cell(tr, s.login);
      cell(tr, s.logout);
      const how = { logged_out: ['Logged out', 'b-out'], timed_out: ['Timed out', 'b-idle'], forced: ['Forced logout', 'b-forced'] }[s.status] || [s.status, 'b-out'];
      cell(tr, '').appendChild(pill(how[0], how[1]));
    });
  }
}

let busy = false;
async function load() {
  if (busy) return;
  busy = true;
  try {
    const r = await fetch('active_sessions.php?feed=1&_=' + Date.now(), { cache: 'no-store', credentials: 'same-origin' });
    if (r.status === 401 || r.redirected) { location.href = 'login.php'; return; }
    const d = await r.json();
    if (!d.ok) throw new Error(d.message || 'error');
    render(d);
    $('live').classList.remove('off'); $('liveText').textContent = 'LIVE';
  } catch (e) {
    $('live').classList.add('off'); $('liveText').textContent = 'OFFLINE';
  } finally { busy = false; }
}

function ask(key, name) {
  pendingKey = key; pendingName = name;
  $('mText').textContent = name + ' will be logged out on their next action and has to sign in again.';
  $('modal').classList.add('show');
}
$('mCancel').addEventListener('click', () => { $('modal').classList.remove('show'); pendingKey = null; });
$('mOk').addEventListener('click', async () => {
  const key = pendingKey;
  $('modal').classList.remove('show');
  if (!key) return;
  try {
    const r = await fetch('active_sessions.php', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'csrf=' + encodeURIComponent(CSRF) + '&key=' + encodeURIComponent(key)
    });
    const d = await r.json();
    toast(d.message || (d.ok ? 'Done' : 'Failed'));
  } catch (e) { toast('Could not reach the server.'); }
  pendingKey = null;
  load();
});

load();
setInterval(load, 5000);
</script>
</body>
</html>