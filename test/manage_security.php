<?php
session_start();
include 'db.php';

if (!isset($_SESSION['admin_logged_in']) && !isset($_SESSION['officer_logged_in'])) {
  header("Location: admin_login.php");
  exit;
}

$isAdmin = isset($_SESSION['admin_logged_in']);

// CSRF token (used by every action form below)
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function generateTempPassword(int $length = 10): string {
  // no look-alike characters (0/O, 1/l/I)
  $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  $max = strlen($chars) - 1;
  $pass = '';
  for ($i = 0; $i < $length; $i++) {
    $pass .= $chars[random_int(0, $max)];
  }
  return $pass;
}

// ALL ACTIONS ARE POST + CSRF-CHECKED
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

  if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
    http_response_code(403);
    exit('Invalid request.');
  }

  // DELETE ACCOUNT
  if (isset($_POST['delete_id'])) {
    $id = (int)$_POST['delete_id'];
    $delete = $conn->prepare("DELETE FROM security WHERE id = ?");
    $delete->bind_param("i", $id);
    $delete->execute();
    header("Location: manage_security.php");
    exit;
  }

  // TOGGLE STATUS
  if (isset($_POST['toggle_id'])) {
    $id = (int)$_POST['toggle_id'];

    $get = $conn->prepare("SELECT status FROM security WHERE id = ?");
    $get->bind_param("i", $id);
    $get->execute();
    $result = $get->get_result();

    if ($result->num_rows > 0) {
      $row = $result->fetch_assoc();
      $newStatus = ($row['status'] === 'ACTIVE') ? 'INACTIVE' : 'ACTIVE';

      $update = $conn->prepare("UPDATE security SET status = ? WHERE id = ?");
      $update->bind_param("si", $newStatus, $id);
      $update->execute();
    }

    header("Location: manage_security.php");
    exit;
  }

  // RESET PASSWORD (admin only)
  if (isset($_POST['reset_id'])) {
    if (!$isAdmin) {
      http_response_code(403);
      exit('Only the admin can reset passwords.');
    }

    $id   = (int)$_POST['reset_id'];
    $temp = generateTempPassword();
    $hash = password_hash($temp, PASSWORD_DEFAULT);

    $upd = $conn->prepare("UPDATE security SET password = ?, must_change_password = 1 WHERE id = ?");
    $upd->bind_param("si", $hash, $id);
    $upd->execute();

    if ($upd->affected_rows > 0) {
      $u = $conn->prepare("SELECT username FROM security WHERE id = ?");
      $u->bind_param("i", $id);
      $u->execute();
      $uname = $u->get_result()->fetch_assoc()['username'] ?? '';
      $_SESSION['flash_temp'] = ['username' => $uname, 'password' => $temp];
    }

    header("Location: manage_security.php");
    exit;
  }
}

// Show the temp password once, then forget it
$flashTemp = $_SESSION['flash_temp'] ?? null;
unset($_SESSION['flash_temp']);

$security = $conn->query("SELECT * FROM security ORDER BY created_at DESC");

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
<title>Manage Security Accounts</title>

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

/* One-time temporary password notice */
.flash { background: var(--gold-soft); border: 1px solid var(--gold); border-radius: 12px; padding: 16px 20px; margin-bottom: 20px; font-size: 13px; }
.flash code { font-size: 16px; font-weight: 700; letter-spacing: .05em; background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 4px 10px; margin: 0 6px; user-select: all; }

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

/* STATUS BADGES */
.badge-active   { background: #e8f8ef; color: #16a34a; }
.badge-inactive { background: #fdeaea; color: #dc2626; }

/* POSITION BADGES */
.badge-officer   { background: #fdf1d8; color: #d97706; }
.badge-personnel { background: #eef3fa; color: var(--navy); }

.row-actions { display: flex; gap: 10px; flex-wrap: wrap; }
.row-actions form { display: inline; }

.btn-toggle { background: #eef3fa; color: var(--navy); border-color: #c7d7ec; }
.btn-toggle:hover { background: #dfeaf7; border-color: var(--gold); }

.btn-delete { background: #fdeaea; color: #dc2626; border-color: #f6c6c6; }
.btn-delete:hover { background: #fad8d8; border-color: #dc2626; box-shadow: 0 8px 24px rgba(220,38,38,0.2); }

@media (max-width: 900px) { table { min-width: 900px; } }

/* ============================================================
   CONFIRM MODAL (replaces the browser "localhost says" popup)
   ============================================================ */

.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  z-index: 9999;
  padding: 20px;
  align-items: center;
  justify-content: center;
  background: rgba(22,35,61,0.55);
  backdrop-filter: blur(6px);
}
.modal-overlay.show { display: flex; }

.modal {
  width: 100%;
  max-width: 400px;
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 28px;
  text-align: center;
  box-shadow: 0 15px 40px rgba(15,36,64,0.25);
  animation: modalIn .18s ease;
}

@keyframes modalIn {
  from { opacity: 0; transform: translateY(8px) scale(.98); }
  to   { opacity: 1; transform: none; }
}

.modal-icon {
  width: 52px; height: 52px;
  margin: 0 auto 16px;
  border-radius: 14px;
  border: 2px dashed #c7d7ec;
  background: #f4f7fb;
  color: var(--navy);
  display: flex; align-items: center; justify-content: center;
}
.modal-icon svg { width: 24px; height: 24px; }
.modal-icon.danger { border-color: #f6c6c6; background: #fdeaea; color: #dc2626; }

.modal h3 { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
.modal p  { font-size: 13px; line-height: 1.55; color: #6b7a94; }

.modal-actions { display: flex; gap: 10px; margin-top: 24px; }
.modal-actions .btn { flex: 1; padding: 12px 16px; }

.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }

.btn-danger { background: #dc2626; border-color: #dc2626; color: #fff; }
.btn-danger:hover { background: #b91c1c; border-color: #b91c1c; box-shadow: 0 8px 24px rgba(220,38,38,0.25); }

@media (prefers-reduced-motion: reduce) {
  .modal { animation: none; }
}
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="admin_dashboard.php" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="users.php" data-tip="Users" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item active" aria-current="page" href="manage_security.php" data-tip="Security Accounts" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
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
      <h1>Manage Security Accounts</h1>
      <p>Activate, deactivate, reset or remove security personnel.</p>
    </div>
    <div style="display:flex; gap:12px; flex-wrap:wrap;">
      <a href="admin_add_security.php" class="btn" style="background:var(--navy); border-color:var(--navy); color:#fff;">Add Security Account</a>
      <a href="admin_dashboard.php" class="btn">Back to Dashboard</a>
    </div>
  </div>

  <?php if ($flashTemp): ?>
    <div class="flash">
      Temporary password for <strong><?= htmlspecialchars($flashTemp['username']) ?></strong>:
      <code><?= htmlspecialchars($flashTemp['password']) ?></code>
      Copy it now. It will not be shown again, and they must change it at next login.
    </div>
  <?php endif; ?>

  <div class="container">
    <div class="table-scroll">
      <table>
        <tr>
          <th>Name</th>
          <th>Username</th>
          <th>Position</th>
          <th>Contact</th>
          <th>Status</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>

        <?php if ($security->num_rows > 0): ?>
          <?php while ($row = $security->fetch_assoc()): ?>
          <?php $uname = htmlspecialchars($row['username'], ENT_QUOTES); ?>
          <tr>
            <td><?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?></td>
            <td><?= htmlspecialchars($row['username']) ?></td>
            <td>
              <span class="badge <?= ($row['position'] ?? '') === 'Security Officer' ? 'badge-officer' : 'badge-personnel' ?>">
                <?= htmlspecialchars($row['position'] ?? 'Security Personnel') ?>
              </span>
            </td>
            <td><?= htmlspecialchars($row['contact_number']) ?></td>
            <td>
              <span class="badge badge-<?= htmlspecialchars(strtolower($row['status'])) ?>">
                <?= htmlspecialchars($row['status']) ?>
              </span>
            </td>
            <td><?= htmlspecialchars($row['created_at']) ?></td>
            <td>
              <div class="row-actions">

                <form method="POST">
                  <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
                  <input type="hidden" name="toggle_id" value="<?= (int)$row['id'] ?>">
                  <button type="submit" class="btn btn-sm btn-toggle">Toggle Status</button>
                </form>

                <?php if ($isAdmin): ?>
                <form method="POST"
                      data-confirm
                      data-confirm-icon="key"
                      data-confirm-type="primary"
                      data-confirm-title="Reset password?"
                      data-confirm-text="A temporary password will be generated for <?= $uname ?>. They must change it at next login."
                      data-confirm-button="Reset Password">
                  <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
                  <input type="hidden" name="reset_id" value="<?= (int)$row['id'] ?>">
                  <button type="submit" class="btn btn-sm btn-toggle">Reset Password</button>
                </form>
                <?php endif; ?>

                <form method="POST"
                      data-confirm
                      data-confirm-icon="trash"
                      data-confirm-type="danger"
                      data-confirm-title="Delete account?"
                      data-confirm-text="<?= $uname ?> will be permanently removed. This cannot be undone."
                      data-confirm-button="Delete">
                  <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
                  <input type="hidden" name="delete_id" value="<?= (int)$row['id'] ?>">
                  <button type="submit" class="btn btn-sm btn-delete">Delete</button>
                </form>

              </div>
            </td>
          </tr>
          <?php endwhile; ?>
        <?php else: ?>
          <tr><td colspan="7" class="empty">No security accounts found.</td></tr>
        <?php endif; ?>
      </table>
    </div>
  </div>

</main>


<!-- ============================================================
     CONFIRM MODAL
     ============================================================ -->

<div class="modal-overlay" id="confirmModal" aria-hidden="true">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="confirmTitle" aria-describedby="confirmText">

    <div class="modal-icon" id="confirmIcon"></div>

    <h3 id="confirmTitle">Are you sure?</h3>
    <p id="confirmText"></p>

    <div class="modal-actions">
      <button type="button" class="btn" id="confirmCancel">Cancel</button>
      <button type="button" class="btn btn-primary" id="confirmOk">Confirm</button>
    </div>

  </div>
</div>

<script>
(function () {

  var overlay   = document.getElementById('confirmModal');
  var iconBox   = document.getElementById('confirmIcon');
  var titleEl   = document.getElementById('confirmTitle');
  var textEl    = document.getElementById('confirmText');
  var cancelBtn = document.getElementById('confirmCancel');
  var okBtn     = document.getElementById('confirmOk');

  var pendingForm = null;
  var lastFocus   = null;

  var ICONS = {
    key:   '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg>',
    trash: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>'
  };

  function openModal(form) {
    pendingForm = form;
    lastFocus   = document.activeElement;

    var type = form.getAttribute('data-confirm-type') || 'primary';

    iconBox.innerHTML = ICONS[form.getAttribute('data-confirm-icon')] || ICONS.key;
    iconBox.className = 'modal-icon' + (type === 'danger' ? ' danger' : '');

    titleEl.textContent = form.getAttribute('data-confirm-title')  || 'Are you sure?';
    textEl.textContent  = form.getAttribute('data-confirm-text')   || '';
    okBtn.textContent   = form.getAttribute('data-confirm-button') || 'Confirm';
    okBtn.className     = 'btn ' + (type === 'danger' ? 'btn-danger' : 'btn-primary');

    overlay.classList.add('show');
    overlay.setAttribute('aria-hidden', 'false');

    // Focus the safe option first
    cancelBtn.focus();
  }

  function closeModal() {
    overlay.classList.remove('show');
    overlay.setAttribute('aria-hidden', 'true');
    pendingForm = null;

    if (lastFocus && typeof lastFocus.focus === 'function') {
      lastFocus.focus();
    }
  }

  // Intercept any form marked with data-confirm
  document.addEventListener('submit', function (e) {
    var form = e.target;

    if (!form.hasAttribute || !form.hasAttribute('data-confirm')) {
      return;
    }

    e.preventDefault();
    openModal(form);
  });

  okBtn.addEventListener('click', function () {
    var form = pendingForm;
    closeModal();

    // form.submit() does not re-trigger the submit event, so no loop
    if (form) form.submit();
  });

  cancelBtn.addEventListener('click', closeModal);

  // Click on the dark backdrop closes the popup
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });

  document.addEventListener('keydown', function (e) {

    if (!overlay.classList.contains('show')) return;

    if (e.key === 'Escape') {
      e.preventDefault();
      closeModal();
      return;
    }

    // Keep Tab focus inside the popup
    if (e.key === 'Tab') {
      var first = cancelBtn;
      var last  = okBtn;

      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });

})();
</script>

</body>
</html>