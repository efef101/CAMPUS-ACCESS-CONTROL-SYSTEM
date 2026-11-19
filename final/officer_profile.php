<?php
include 'db.php';
include_once 'auth.php';
require_once 'activity_log.php';

// Only a logged-in security officer can open their own profile
require_auth($conn, ['officer']);

$loggedName = $_SESSION['officer_username'] ?? 'Officer';
$staffId = (int)($_SESSION['staff_ids']['officer'] ?? 0);

$errors = [];
$saved  = false;

/* ===== SAVE (own row only; only the contact number is editable here) ===== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $staffId > 0) {
    csrf_check();

    // Names are set by the administrator; username and contact number can be changed here
    $username = trim($_POST['username'] ?? '');
    $contact  = trim($_POST['contact_number'] ?? '');

    if (!preg_match('/^[A-Za-z0-9._-]{3,30}$/', $username)) $errors[] = 'Username must be 3-30 characters: letters, numbers, dots, underscores or hyphens.';

    if ($contact !== '' && !preg_match('/^\+?[0-9][0-9\s-]{6,19}$/', $contact)) $errors[] = 'Enter a valid contact number (digits only, may start with +).';

    // Usernames must be unique (the row itself is excluded)
    if (!$errors) {
        $dup = $conn->prepare("SELECT id FROM staff WHERE username = ? AND id <> ? LIMIT 1");
        $dup->bind_param("si", $username, $staffId);
        $dup->execute();
        $taken = $dup->get_result()->num_rows > 0;
        $dup->close();
        if ($taken) $errors[] = 'That username is already taken.';
    }

    if (!$errors) {
        $oldName = $loggedName;
        $upd = $conn->prepare("UPDATE staff SET username = ?, contact_number = ? WHERE id = ? AND role = 'officer'");
        $upd->bind_param("ssi", $username, $contact, $staffId);
        $upd->execute();
        $upd->close();
        $_SESSION['officer_username'] = $username;   // sidebar and login name follow the new username
        log_activity($conn, 'UPDATE PROFILE', $username, $oldName !== $username ? 'was ' . $oldName : '', 'officer');
        header("Location: officer_profile.php?saved=1");
        exit;
    }
}

if (isset($_GET['saved'])) $saved = true;

/* ===== LOAD (read the current row, also after a failed save) ===== */
$me = null;
if ($staffId > 0) {
    $stmt = $conn->prepare("SELECT username, first_name, last_name, contact_number, status, created_at FROM staff WHERE id = ? AND role = 'officer' LIMIT 1");
    $stmt->bind_param("i", $staffId);
    $stmt->execute();
    $me = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

// Show what was typed when the save failed
if ($me && $errors) {
    $me['username']       = trim($_POST['username'] ?? $me['username']);
    $me['contact_number'] = trim($_POST['contact_number'] ?? $me['contact_number']);
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

$fullName = $me ? trim($me['first_name'] . ' ' . $me['last_name']) : '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Profile</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root { --ink: #16233d; --navy: #1c3a5e; --line: #dce4ef; --muted: #8a9bb5; --gold: #f0b429; --gold-soft: #fffdf5; --gold-glow: 0 8px 24px rgba(240,180,41,0.25); }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fafbfd; min-height: 100vh; display: flex; color: var(--ink); }
svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.sidebar { width: 220px; flex-shrink: 0; background: linear-gradient(180deg, #1c3a5e, #0f2440); border-right: 1px solid #0f2440; height: 100vh; position: sticky; top: 0; display: flex; flex-direction: column; align-items: stretch; padding: 24px 18px; gap: 12px; }
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
.sidebar .nav-item:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; border-radius: 12px; }
.sidebar .user-divider { margin-top: auto; }
.sidebar-user { display: flex; align-items: center; gap: 12px; width: 100%; padding: 4px 0; text-decoration: none; border-radius: 12px; }
.sidebar-user:hover .su-name, .sidebar-user:focus-visible .su-name { color: #fff; }
.sidebar-user:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }
.su-avatar { width: 40px; height: 40px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; background: rgba(169,196,232,0.15); border: 1px solid rgba(169,196,232,0.35); color: #a9c4e8; font-size: 15px; font-weight: 700; }
.su-text { display: flex; flex-direction: column; min-width: 0; }
.su-name { font-size: 13px; font-weight: 600; color: #a9c4e8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.su-label { font-size: 10px; font-style: italic; color: rgba(169,196,232,0.6); margin-top: 1px; }
.sidebar .logout-item { margin-top: 0; }

/* content area: the card sits in the middle of it, both ways */
.main { flex: 1; min-width: 0; padding: 32px; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; }
.header { text-align: center; margin-bottom: 24px; }
.header h1 { font-size: 22px; font-weight: 600; }
.header p { font-size: 13px; color: var(--muted); margin-top: 4px; }

.profile { width: 100%; max-width: 520px; background: #fff; border: 1px solid var(--line); border-radius: 14px; box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 24px; }
.profile-head { display: flex; align-items: center; gap: 16px; padding-bottom: 18px; margin-bottom: 8px; border-bottom: 1px solid #eef2f8; }
.profile-avatar { width: 56px; height: 56px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; background: #eef3fa; border: 1px solid #c7d7ec; color: var(--navy); font-size: 22px; font-weight: 700; }
.profile-name { font-size: 18px; font-weight: 600; }
.profile-role { font-size: 13px; color: #d97706; font-weight: 600; margin-top: 2px; }

.profile-row { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 12px 0; border-bottom: 1px solid #eef2f8; font-size: 14px; }
.profile-row:last-of-type { border-bottom: none; }
.profile-row > span:first-child { color: var(--muted); flex-shrink: 0; }
.profile-row > span:last-child { color: var(--ink); font-weight: 500; text-align: right; }

.field { display: flex; flex-direction: column; gap: 6px; padding: 10px 0; border-bottom: 1px solid #eef2f8; }
.field label { font-size: 12px; color: var(--muted); }
.field input { width: 100%; padding: 10px 12px; font-size: 14px; color: var(--ink); background: #fff; border: 1px solid var(--line); border-radius: 8px; }
.field input:focus { outline: none; border-color: var(--gold); box-shadow: var(--gold-glow); }

.btn { display: inline-block; margin-top: 16px; padding: 11px 20px; border-radius: 12px; border: 1px solid var(--navy); background: var(--navy); color: #fff; font-size: 13px; font-weight: 600; cursor: pointer; }
.btn:hover { background: var(--ink); border-color: var(--gold); }
.btn:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }

.notice { margin-top: 14px; padding: 10px 12px; border-radius: 8px; font-size: 13px; }
.notice.ok { background: #e8f8ef; color: #15803d; }
.notice.err { background: #fdeaea; color: #b42318; }
.notice ul { padding-left: 18px; }

@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .sidebar .logo-text { display: none; }
  .su-text { display: none; }
  .sidebar-user { justify-content: center; }
  .sidebar .logo img { width: 40px; height: 40px; }
  .main { padding: 20px; }
}
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
  <a class="nav-item" href="officer_dashboard.php" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="officer_users.php" data-tip="Users" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item" href="officer_security.php" data-tip="Security Accounts" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
  <a class="nav-item" href="officer_logs.php" data-tip="Access Logs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item" href="security_summary.php?from=officer" data-tip="Security Overview" aria-label="Security Overview"><span class="nav-icon"><?= icon('chart') ?></span><span class="nav-label">Security Overview</span></a>
  <div class="sidebar-divider user-divider"></div>
  <a class="sidebar-user" href="officer_profile.php" title="My profile" aria-current="page">
    <span class="su-avatar"><?= htmlspecialchars(strtoupper(substr($loggedName, 0, 1))) ?></span>
    <span class="su-text">
      <span class="su-name"><?= htmlspecialchars($loggedName) ?></span>
      <span class="su-label">Logged in</span>
    </span>
  </a>
  <a class="nav-item logout-item" href="officer_logout.php" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<main class="main">

  <div class="header">
    <h1>My Profile</h1>
    <p>.</p>
  </div>

  <?php if ($me): ?>
  <div class="profile">
    <div class="profile-head">
      <span class="profile-avatar"><?= htmlspecialchars(strtoupper(substr($me['first_name'] ?: $me['username'], 0, 1))) ?></span>
      <div>
        <div class="profile-name"><?= htmlspecialchars($fullName !== '' ? $fullName : $me['username']) ?></div>
        <div class="profile-role">Security Officer</div>
      </div>
    </div>

    <?php if ($saved && !$errors): ?>
      <div class="notice ok">Profile saved.</div>
    <?php endif; ?>
    <?php if ($errors): ?>
      <div class="notice err"><ul>
        <?php foreach ($errors as $e): ?><li><?= htmlspecialchars($e) ?></li><?php endforeach; ?>
      </ul></div>
    <?php endif; ?>

    <form method="POST" action="officer_profile.php">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars(csrf_token()) ?>">

      <div class="profile-row"><span>First name</span><span><?= htmlspecialchars($me['first_name']) ?></span></div>
      <div class="profile-row"><span>Last name</span><span><?= htmlspecialchars($me['last_name']) ?></span></div>
      <div class="field">
        <label for="contact_number">Contact number</label>
        <input type="tel" id="contact_number" name="contact_number" maxlength="20" value="<?= htmlspecialchars($me['contact_number'] ?? '') ?>">
      </div>

      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" maxlength="30" required pattern="[A-Za-z0-9._-]{3,30}" value="<?= htmlspecialchars($me['username']) ?>">
      </div>
      <div class="profile-row"><span>Status</span><span><?= htmlspecialchars($me['status']) ?></span></div>
      <div class="profile-row"><span>Account created</span><span><?= htmlspecialchars(date('M j, Y', strtotime($me['created_at']))) ?></span></div>

      <button type="submit" class="btn">Save changes</button>
    </form>
  </div>
  <?php else: ?>
  <p>Your profile could not be found. Please log in again.</p>
  <?php endif; ?>

</main>

</body>
</html>