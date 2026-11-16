<?php
session_start();
date_default_timezone_set('Asia/Manila');
include 'db.php';
include_once 'auth.php';
if (is_file(__DIR__ . '/activity_log.php')) require_once __DIR__ . '/activity_log.php';

// Only Security Personnel can post announcements
require_auth($conn, ['personnel']);

$poster     = $_SESSION['security_username'] ?? 'security';
$posterRole = 'Security Personnel';
$roleKey    = 'security';
$self       = 'announcements.php';

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));


// Older installs: add the importance column once
$col = $conn->query("SHOW COLUMNS FROM announcements LIKE 'importance'");
if ($col && $col->num_rows === 0) {
  $conn->query("ALTER TABLE announcements ADD COLUMN importance VARCHAR(10) NOT NULL DEFAULT 'Normal' AFTER audience");
}

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function note($conn, $action, $target, $details, $roleKey) {
  if (function_exists('log_activity')) log_activity($conn, $action, $target, $details, $roleKey);
}

$audiences = ['All' => 'Everyone', 'Student' => 'Students', 'Faculty' => 'Faculty', 'Staff' => 'Staff', 'Alumni' => 'Alumni'];
$msg = $_GET['msg'] ?? '';
$err = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
    $err = 'Session expired. Please try again.';
  } else {
    $do = $_POST['do'] ?? '';

    if ($do === 'post') {
      $title = mb_substr(trim($_POST['title'] ?? ''), 0, 120);
      $body  = mb_substr(trim($_POST['message'] ?? ''), 0, 1000);
      $aud   = $_POST['audience'] ?? 'All';
      $imp   = (($_POST['importance'] ?? '') === 'Urgent') ? 'Urgent' : 'Normal';
      $exp   = trim($_POST['expires_at'] ?? '');
      $d     = DateTime::createFromFormat('Y-m-d', $exp);
      $expSql = ($d && $d->format('Y-m-d') === $exp) ? $exp : null;

      if ($title === '' || $body === '') {
        $err = 'Please enter a title and a message.';
      } elseif (!isset($audiences[$aud])) {
        $err = 'Invalid audience.';
      } elseif ($expSql !== null && $expSql < date('Y-m-d')) {
        $err = 'The "show until" date cannot be in the past.';
      } else {
        $st = $conn->prepare("INSERT INTO announcements (title, message, audience, importance, created_by_name, created_by_staff_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $staffId = auth_staff_id() ?: null;
        $st->bind_param('sssssis', $title, $body, $aud, $imp, $poster, $staffId, $expSql);
        $st->execute();
        note($conn, 'POST ANNOUNCEMENT', $title, 'For ' . $audiences[$aud] . ($imp === 'Urgent' ? ' (Urgent)' : ''), $roleKey);
        header("Location: $self?msg=posted"); exit;
      }

    } elseif ($do === 'toggle' || $do === 'delete') {
      $id = (int)($_POST['id'] ?? 0);
      $st = $conn->prepare("SELECT title, active FROM announcements WHERE id = ?");
      $st->bind_param('i', $id);
      $st->execute();
      $a = $st->get_result()->fetch_assoc();
      if ($a) {
        if ($do === 'toggle') {
          $new = $a['active'] ? 0 : 1;
          $u = $conn->prepare("UPDATE announcements SET active = ? WHERE id = ?");
          $u->bind_param('ii', $new, $id);
          $u->execute();
          note($conn, $new ? 'SHOW ANNOUNCEMENT' : 'HIDE ANNOUNCEMENT', $a['title'], '', $roleKey);
          header("Location: $self?msg=" . ($new ? 'shown' : 'hidden')); exit;
        } else {
          $x = $conn->prepare("DELETE FROM announcements WHERE id = ?");
          $x->bind_param('i', $id);
          $x->execute();
          note($conn, 'DELETE ANNOUNCEMENT', $a['title'], '', $roleKey);
          header("Location: $self?msg=deleted"); exit;
        }
      }
    }
  }
}

$msgText = ['posted' => 'Announcement posted. Members will see it in My Logs.', 'shown' => 'Announcement is visible again.',
            'hidden' => 'Announcement hidden. Members no longer see it.', 'deleted' => 'Announcement deleted.'][$msg] ?? '';

$list = $conn->query("SELECT id, title, message, audience, importance, created_by_name AS posted_by, 'Security Personnel' AS posted_role, expires_at, active, created_at FROM announcements ORDER BY created_at DESC, id DESC LIMIT 100");

function icon($name) {
  $paths = [
    'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'scan'   => '<path d="M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3"/><path d="M4 12h16"/>',
    'visitor'=> '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6 16c.5-1.5 1.7-2 3-2s2.5.5 3 2M15 10h3M15 13h3"/>',
    'mega'   => '<path d="M3 11v2a1 1 0 001 1h2l7 4V6L6 10H4a1 1 0 00-1 1z"/><path d="M16 9a4 4 0 010 6M19 7a7 7 0 010 10"/>',
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
<title>Announcements</title>
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
  width: 44px; height: 44px; border-radius: 12px; object-fit: cover;
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

/* MAIN + HEADER */
.main { flex: 1; min-width: 0; padding: 32px; }
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }

/* Shared button look: white, soft border, yellow hover */
.btn {
  display: inline-block;
  text-decoration: none;
  padding: 11px 20px;
  border-radius: 12px;
  border: 1px solid var(--line);
  background: #fff;
  color: var(--ink);
  font-size: 13px; font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: transform .15s, background .15s, border-color .15s, box-shadow .15s;
}
.btn:hover {
  transform: translateY(-2px);
  background: var(--gold-soft);
  border-color: var(--gold);
  box-shadow: var(--gold-glow);
}
.btn:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }
.btn-sm { padding: 8px 14px; font-size: 12px; }

/* Container card */
.container {
  background: #fff;
  border-radius: 14px;
  border: 1px solid var(--line);
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  overflow: hidden;
}
.empty { text-align: center; padding: 40px; color: #b7c3d6; font-size: 13px; }

@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
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
}
@media (prefers-reduced-motion: reduce) {
  .btn, .sidebar .nav-icon { transition: none; }
}

/* TABLE */
.table-scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th {
  text-align: left; padding: 16px 18px;
  font-size: 11px; color: #96a6c0;
  text-transform: uppercase; letter-spacing: 0.06em;
  border-bottom: 1px solid #eef2f8; background: #f4f7fb;
}
td {
  padding: 16px 18px; border-bottom: 1px solid #eef2f8;
  font-size: 13px; color: #3c4a63; vertical-align: middle;
}
tr:hover td { color: var(--ink); background: #f7fafd; }
.badge { display: inline-block; padding: 3px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase; }

/* ROLE BADGES */
.student { background: #eef3fa; color: #1c3a5e; }
.faculty { background: #f3ecfb; color: #7c3aed; }
.staff   { background: #e8f8ef; color: #16a34a; }
.alumni  { background: #fdf1d8; color: #d97706; }
.visitor { background: #eef2f8; color: #6b7a94; }

/* BARCODE */
.barcode-box {
  background: #fff; border-radius: 10px; padding: 10px;
  display: inline-flex; justify-content: center; align-items: center;
  border: 1px solid #eef2f8;
}
.barcode { max-width: 180px; }

/* ACTION BUTTON */
.action-btn { background: #fdf1d8; color: #b4650a; border-color: #f0d79a; }
.action-btn:hover { background: #fbe6b8; border-color: var(--gold); }
.muted-text { color: var(--muted); font-size: 12px; }

@media (max-width: 900px) { table { min-width: 900px; } }

/* ANNOUNCEMENTS */
.alert { padding: 12px 16px; border-radius: 12px; font-size: 13px; margin-bottom: 16px; }
.alert.ok  { background: #e8f8ef; color: #15803d; border: 1px solid #bfe6cf; }
.alert.err { background: #fdeaea; color: #b91c1c; border: 1px solid #f3c1c1; }
.form-card { padding: 22px; margin-bottom: 20px; }
.form-card h3 { font-size: 15px; margin-bottom: 14px; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.field { margin-bottom: 14px; }
.field label { display: block; font-size: 12px; font-weight: 600; color: #6b7a94; margin-bottom: 6px; }
.field input, .field select, .field textarea {
  width: 100%; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--line);
  background: #f4f7fb; font: 14px inherit; font-family: inherit; color: var(--ink);
}
.field textarea { min-height: 110px; resize: vertical; }
.field input:focus, .field select:focus, .field textarea:focus { outline: none; border-color: #6d8fca; background: #fff; }
.hint { font-size: 11px; color: var(--muted); margin-top: 4px; }
.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); color: #fff; }
.btn-danger { color: #b91c1c; }
.status-visible { background: #e8f8ef; color: #16a34a; }
.status-hidden  { background: #eef2f8; color: #6b7a94; }
.status-urgent  { background: #dc2626; color: #fff; margin-left: 6px; }
.status-expired { background: #fdf1d8; color: #d97706; }
.row-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.row-actions form { display: inline; }
.msg-cell { max-width: 320px; white-space: pre-line; color: #6b7a94; font-size: 12px; }
@media (max-width: 700px) { .grid2 { grid-template-columns: 1fr; } .main { padding-bottom: 96px; } }
</style>
<link rel="stylesheet" href="mobile.css">
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="dashboard.php" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="security_logs.php" data-tip="Access Logs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item" href="visitor_register.php" data-tip="Register Visitor" aria-label="Register Visitor"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Register Visitor</span></a>
  <a class="nav-item active" href="announcements.php" data-tip="Announcements" aria-label="Announcements" aria-current="page"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Announcements</span></a>
  <a class="nav-item logout-item" href="security_logout.php" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<!-- MAIN -->
<main class="main">

  <div class="header">
    <div class="header-left">
      <h1>Announcements</h1>
      <p>Post notices that members see when they open My Logs.</p>
    </div>
    <a href="dashboard.php" class="btn">Back to Dashboard</a>
  </div>

  <?php if ($msgText): ?><div class="alert ok"><?= e($msgText) ?></div><?php endif; ?>
  <?php if ($err): ?><div class="alert err"><?= e($err) ?></div><?php endif; ?>

  <div class="container form-card">
    <h3>New announcement</h3>
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
      <input type="hidden" name="do" value="post">

      <div class="field">
        <label for="title">Title</label>
        <input type="text" id="title" name="title" maxlength="120" required value="<?= e($_POST['title'] ?? '') ?>">
      </div>

      <div class="field">
        <label for="message">Message</label>
        <textarea id="message" name="message" maxlength="1000" required><?= e($_POST['message'] ?? '') ?></textarea>
        <div class="hint">Up to 1000 characters.</div>
      </div>

      <div class="grid2">
        <div class="field">
          <label for="importance">Importance</label>
          <select id="importance" name="importance">
            <option value="Normal">Normal</option>
            <option value="Urgent">Urgent (shown in red at the top)</option>
          </select>
        </div>
        <div class="field">
          <label for="audience">Who will see it</label>
          <select id="audience" name="audience">
            <?php foreach ($audiences as $k => $label): ?>
              <option value="<?= e($k) ?>"><?= e($label) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="field">
          <label for="expires_at">Show until (optional)</label>
          <input type="date" id="expires_at" name="expires_at" min="<?= e(date('Y-m-d')) ?>">
          <div class="hint">Leave empty to keep it visible until you hide it.</div>
        </div>
      </div>

      <button class="btn btn-primary" type="submit">Post announcement</button>
    </form>
  </div>

  <div class="container">
    <div class="table-scroll">
      <table>
        <tr>
          <th>Announcement</th>
          <th>For</th>
          <th>Posted by</th>
          <th>Posted</th>
          <th>Status</th>
          <th>Action</th>
        </tr>
        <?php if ($list && $list->num_rows > 0): while ($a = $list->fetch_assoc()):
          $expired = $a['expires_at'] && $a['expires_at'] < date('Y-m-d');
          if (!$a['active'])      { $stCls = 'status-hidden';  $stTxt = 'Hidden'; }
          elseif ($expired)       { $stCls = 'status-expired'; $stTxt = 'Expired'; }
          else                    { $stCls = 'status-visible'; $stTxt = 'Visible'; }
        ?>
        <tr>
          <td>
            <strong><?= e($a['title']) ?></strong>
            <?php if (($a['importance'] ?? '') === 'Urgent'): ?><span class="badge status-urgent">Urgent</span><?php endif; ?>
            <div class="msg-cell"><?= e($a['message']) ?></div>
          </td>
          <td><?= e($audiences[$a['audience']] ?? $a['audience']) ?></td>
          <td><?= e($a['posted_by']) ?><div class="muted-text"><?= e($a['posted_role']) ?></div></td>
          <td><?= e(date('M j, Y g:i A', strtotime($a['created_at']))) ?>
            <?php if ($a['expires_at']): ?><div class="muted-text">Until <?= e(date('M j, Y', strtotime($a['expires_at']))) ?></div><?php endif; ?></td>
          <td><span class="badge <?= $stCls ?>"><?= $stTxt ?></span></td>
          <td>
            <div class="row-actions">
              <form method="post">
                <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                <input type="hidden" name="do" value="toggle">
                <input type="hidden" name="id" value="<?= (int)$a['id'] ?>">
                <button class="btn btn-sm" type="submit"><?= $a['active'] ? 'Hide' : 'Show' ?></button>
              </form>
              <form method="post" onsubmit="return confirm('Delete this announcement for good?')">
                <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                <input type="hidden" name="do" value="delete">
                <input type="hidden" name="id" value="<?= (int)$a['id'] ?>">
                <button class="btn btn-sm btn-danger" type="submit">Delete</button>
              </form>
            </div>
          </td>
        </tr>
        <?php endwhile; else: ?>
          <tr><td colspan="6" class="empty">No announcements yet.</td></tr>
        <?php endif; ?>
      </table>
    </div>
  </div>

</main>
</body>
</html>