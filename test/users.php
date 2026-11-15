<?php
session_start();
include 'db.php';
require_once 'activity_log.php';
$isAdmin = !empty($_SESSION['admin_logged_in']);

if (!isset($_SESSION['admin_logged_in']) && !isset($_SESSION['officer_logged_in'])) {
  header("Location: admin_login.php");
  exit;
}

/* MARK AS ALUMNI */
if (isset($_GET['alumni'])) {
  $id = intval($_GET['alumni']);
  $who = $conn->prepare("SELECT id_number, first_name, last_name, role FROM users WHERE id=?");
  $who->bind_param("i", $id);
  $who->execute();
  $wr = $who->get_result()->fetch_assoc();
  /* only students can become alumni */
  if (!$wr || strtolower($wr['role']) !== 'student') { header("Location: users.php"); exit; }
  $stmt = $conn->prepare("UPDATE users SET role='Alumni' WHERE id=?");
  $stmt->bind_param("i", $id);
  $stmt->execute();
  log_activity($conn, 'MARK ALUMNI', trim($wr['first_name'] . ' ' . $wr['last_name']), 'ID ' . $wr['id_number'], $isAdmin ? 'admin' : 'officer');
  header("Location: users.php");
  exit;
}

/* UNDO ALUMNI (for a misclick) */
if (isset($_GET['undo_alumni'])) {
  $id = intval($_GET['undo_alumni']);
  $who = $conn->prepare("SELECT id_number, first_name, last_name, role FROM users WHERE id=?");
  $who->bind_param("i", $id);
  $who->execute();
  $wr = $who->get_result()->fetch_assoc();
  if ($wr && strtolower($wr['role']) === 'alumni' && can_undo_alumni($conn, $wr['id_number'])) {
    $stmt = $conn->prepare("UPDATE users SET role='Student' WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    log_activity($conn, 'UNDO ALUMNI', trim($wr['first_name'] . ' ' . $wr['last_name']), 'ID ' . $wr['id_number'], $isAdmin ? 'admin' : 'officer');
  }
  header("Location: users.php");
  exit;
}

$result = $conn->query("SELECT * FROM users");

// Inline SVG icons (same set as the dashboard)
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
<title>Registered Users</title>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jsbarcode/3.11.5/JsBarcode.all.min.js"></script>

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
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="admin_dashboard.php" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item active" aria-current="page" href="users.php" data-tip="Users" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item" href="manage_security.php" data-tip="Security Accounts" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
  <a class="nav-item" href="admin_logs.php" data-tip="Access Logs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item" href="security_summary.php?from=admin" data-tip="Security Summary" aria-label="Security Summary"><span class="nav-icon"><?= icon('chart') ?></span><span class="nav-label">Security Summary</span></a>
  <a class="nav-item" href="authentication_logs.php?from=admin" data-tip="Activity Logs" aria-label="Activity Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Activity Logs</span></a>
  <a class="nav-item" href="active_sessions.php?from=admin" data-tip="Active Sessions" aria-label="Active Sessions"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Active Sessions</span></a>
  <a class="nav-item logout-item" href="admin_logout.php" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<!-- MAIN -->
<main class="main">

  <div class="header">
    <div class="header-left">
      <h1>Registered Users</h1>
      <p>Manage and view all registered campus members.</p>
    </div>
    <a href="admin_dashboard.php" class="btn">Back to Dashboard</a>
  </div>

  <div class="container">
    <div class="table-scroll">
      <table>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Role</th>
          <th>Barcode</th>
          <th>Action</th>
        </tr>

        <?php if ($result->num_rows > 0): ?>
          <?php while ($row = $result->fetch_assoc()): ?>
          <tr>
            <td><?= htmlspecialchars($row['id_number']) ?></td>
            <td><?= htmlspecialchars($row['first_name'] . " " . $row['last_name']) ?></td>
            <td>
              <span class="badge <?= htmlspecialchars(strtolower($row['role'])) ?>">
                <?= htmlspecialchars($row['role']) ?>
              </span>
            </td>
            <td>
              <div class="barcode-box">
                <svg class="barcode" data-code="<?= htmlspecialchars($row['id_number']) ?>"></svg>
              </div>
            </td>
            <td>
              <?php if (strtolower($row['role']) === 'student'): ?>
                <a class="btn btn-sm action-btn"
                   href="users.php?alumni=<?= (int)$row['id'] ?>"
                   onclick="return confirm('Convert this user to Alumni?')">Mark as Alumni</a>
              <?php else: ?>
                <?php if (strtolower($row['role']) === 'alumni'): ?>
                  <span class="muted-text">Already Alumni</span>
                  <?php if (can_undo_alumni($conn, $row['id_number'])): ?>
                    <a class="btn btn-sm" href="users.php?undo_alumni=<?= (int)$row['id'] ?>"
                       onclick="return confirm('Undo? This user will go back to Student.')">Undo</a>
                  <?php endif; ?>
                <?php else: ?>
                  <span class="muted-text">-</span>
                <?php endif; ?>
              <?php endif; ?>
            </td>
          </tr>
          <?php endwhile; ?>
        <?php else: ?>
          <tr><td colspan="5" class="empty">No registered users found.</td></tr>
        <?php endif; ?>
      </table>
    </div>
  </div>

</main>

<script>
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".barcode").forEach(function (el) {
    var code = el.getAttribute("data-code");
    if (code && /^[0-9]{1,8}$/.test(code)) {
      JsBarcode(el, code, {
        format: "CODE128", width: 2, height: 50,
        displayValue: true, background: "#ffffff", lineColor: "#000000"
      });
    } else {
      el.outerHTML = '<span class="muted-text">Invalid ID</span>';
    }
  });
});
</script>

</body>
</html>