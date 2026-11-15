<?php
session_start();
include 'db.php';

// Only logged-in security personnel can open this page or register visitors
if (!isset($_SESSION['security_logged_in'])) {
  header("Location: login.php");
  exit;
}

header("Cache-Control: no-cache, no-store, must-revalidate");

// CSRF token
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$success = '';
$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
    $error = "Invalid request. Please try again.";
  } else {

    $qr_code = trim($_POST['qr_code'] ?? '');
    $name = trim($_POST['name'] ?? '');
    $purpose = trim($_POST['purpose'] ?? '');
    $destination = trim($_POST['destination'] ?? '');

    if (!$qr_code || !$name || !$purpose || !$destination) {
      $error = "All fields are required.";
    } else {

      $delete = $conn->prepare("DELETE FROM visitors WHERE qr_code=?");
      $delete->bind_param("s", $qr_code);
      $delete->execute();

      $stmt = $conn->prepare("INSERT INTO visitors (qr_code, name, purpose, destination) VALUES (?, ?, ?, ?)");
      $stmt->bind_param("ssss", $qr_code, $name, $purpose, $destination);

      if ($stmt->execute()) {
        $success = "Visitor registered successfully.";
      } else {
        error_log("Visitor register failed: " . $stmt->error);
        $error = "Could not register the visitor. Please try again.";
      }
    }
  }
}

// Inline SVG icons (same set as the dashboards)
function icon($name) {
  $paths = [
    'home'    => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'scan'    => '<path d="M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3"/><path d="M4 12h16"/>',
    'list'    => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'mega' => '<path d="M3 11v2a1 1 0 001 1h2l7 4V6L6 10H4a1 1 0 00-1 1z"/><path d="M16 9a4 4 0 010 6M19 7a7 7 0 010 10"/>',
    'visitor' => '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6 16c.5-1.5 1.7-2 3-2s2.5.5 3 2M15 10h3M15 13h3"/>',
    'add'     => '<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6.5 7-6.5M18 14v6M15 17h6"/>',
    'logout'  => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    'check'   => '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/>',
    'alert'   => '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5h.01"/>',
  ];
  return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register Visitor</title>

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

/* MAIN */
.main { flex: 1; min-width: 0; padding: 32px; }

/* HEADER */
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }

.btn, .logout {
  display: inline-block;
  text-decoration: none;
  border-radius: 12px;
  border: 1px solid var(--line);
  background: #fff;
  color: var(--ink);
  font-family: inherit;
  font-size: 13px; font-weight: 600;
  cursor: pointer;
  transition: transform .15s, background .15s, border-color .15s, box-shadow .15s;
}
.btn { padding: 11px 24px; }
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

/* FORM CARD */
.form-card {
  background: #fff;
  border-radius: 14px;
  border: 1px solid var(--line);
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  padding: 28px;
  width: 100%;
  max-width: 520px;
  margin: 0 auto;
  transition: border-color .2s, box-shadow .2s;
}
.form-card:hover { border-color: var(--gold); box-shadow: var(--gold-glow); }

.form-card h3 {
  font-size: 14px; font-weight: 600; margin-bottom: 20px;
  display: flex; align-items: center; gap: 12px;
}
.form-card h3 .icon {
  width: 36px; height: 36px; flex-shrink: 0;
  border-radius: 12px; border: 2px dashed #c7d7ec; background: #f4f7fb;
  display: flex; align-items: center; justify-content: center; color: var(--navy);
}
.form-card h3 .icon svg { width: 18px; height: 18px; }

/* FORM FIELDS */
.form-group { margin-bottom: 16px; }

.form-group label {
  display: block;
  font-size: 11px; font-weight: 600; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.06em;
  margin-bottom: 6px;
}

.form-group input {
  width: 100%;
  padding: 10px 14px;
  background: #f8fafc;
  border: 1px solid var(--line);
  border-radius: 10px;
  color: var(--ink);
  font-size: 13px;
  font-family: inherit;
  outline: none;
  transition: border-color .2s, background .2s, box-shadow .2s;
}
.form-group input::placeholder { color: #a3b3cc; }
.form-group input:focus {
  border-color: var(--gold);
  background: #fff;
  box-shadow: 0 0 0 3px rgba(240,180,41,0.18);
}

.form-actions { margin-top: 8px; }

/* ALERTS */
.alert {
  padding: 12px 16px;
  border-radius: 12px;
  font-size: 13px;
  margin: 0 auto 20px;
  max-width: 520px;
  display: flex; align-items: center; gap: 10px;
  max-height: 100px;
  overflow: hidden;
  transition: opacity .4s ease, transform .4s ease, max-height .4s ease,
              padding .4s ease, margin .4s ease, border-width .4s ease;
}
.alert svg { width: 18px; height: 18px; flex-shrink: 0; }
.alert-success { background: #e8f8ef; border: 1px solid #bdeccf; color: #16a34a; }
.alert-error   { background: #fdeaea; border: 1px solid #f6c6c6; color: #dc2626; }

/* Fade-out state (added by JS after 5 seconds) */
.alert.hide {
  opacity: 0;
  transform: translateY(-6px);
  max-height: 0;
  padding-top: 0;
  padding-bottom: 0;
  margin-bottom: 0;
  border-width: 0;
}

/* RESPONSIVE */
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
  .btn, .logout, .form-card, .sidebar .nav-icon, .alert { transition: none; }
}
</style>

</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="dashboard.php" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="scanner_hw.php" data-tip="Scanner" aria-label="Scanner"><span class="nav-icon"><?= icon('scan') ?></span><span class="nav-label">Scanner</span></a>
  <a class="nav-item" href="security_logs.php" data-tip="Logs" aria-label="Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Logs</span></a>
  <a class="nav-item active" href="visitor_register.php" data-tip="Register Visitor" aria-label="Register Visitor" aria-current="page"><span class="nav-icon"><?= icon('visitor') ?></span><span class="nav-label">Register Visitor</span></a>
  <a class="nav-item" href="announcements.php" data-tip="Announcements" aria-label="Announcements"><span class="nav-icon"><?= icon('mega') ?></span><span class="nav-label">Announcements</span></a>
  <a class="nav-item logout-item" href="security_logout.php" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<!-- MAIN -->
<main class="main">

  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <h1>Register Visitor</h1>
      <p><?= date('l, F j, Y') ?></p>
    </div>
    <a href="security_logout.php" class="logout">Logout</a>
  </div>

  <!-- ALERTS -->
  <?php if ($success): ?>
    <div class="alert alert-success" role="status"><?= icon('check') ?> <?= htmlspecialchars($success) ?></div>
  <?php endif; ?>
  <?php if ($error): ?>
    <div class="alert alert-error" role="alert"><?= icon('alert') ?> <?= htmlspecialchars($error) ?></div>
  <?php endif; ?>

  <!-- FORM -->
  <div class="form-card">
    <h3><span class="icon"><?= icon('visitor') ?></span> Visitor Details</h3>
    <form method="POST">

      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">

      <div class="form-group">
        <label for="qr_code">QR Code</label>
        <input type="text" id="qr_code" name="qr_code" placeholder="Enter visitor QR code" required autofocus>
      </div>

      <div class="form-group">
        <label for="name">Visitor Name</label>
        <input type="text" id="name" name="name" placeholder="Full name" required>
      </div>

      <div class="form-group">
        <label for="purpose">Purpose</label>
        <input type="text" id="purpose" name="purpose" placeholder="Purpose of Visit" required>
      </div>

      <div class="form-group">
        <label for="destination">Destination</label>
        <input type="text" id="destination" name="destination" placeholder="Where are they going?" required>
      </div>

      <div class="form-actions">
        <button type="submit" class="btn btn-primary">Register Visitor</button>
      </div>

    </form>
  </div>

</main>

<script>
  // Auto-dismiss alerts after 5 seconds
  document.querySelectorAll('.alert').forEach(function (alertEl) {
    setTimeout(function () {
      alertEl.classList.add('hide');
      setTimeout(function () { alertEl.remove(); }, 400);
    }, 5000);
  });
</script>

</body>
</html>