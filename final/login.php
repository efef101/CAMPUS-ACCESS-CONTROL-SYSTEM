<?php
session_start();
include 'db.php';

$error = '';

// One row in auth_logs. A logging problem must never stop someone from logging in.
function logAuth($conn, $username, $action, $status, $staffId = null) {
  try {
    $username = substr((string)$username, 0, 100);
    $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);   // REMOTE_ADDR only: headers can be faked
    $q = $conn->prepare("INSERT INTO auth_logs (staff_id, username_snapshot, action, status, ip_address) VALUES (?, ?, ?, ?, ?)");
    $q->bind_param("issss", $staffId, $username, $action, $status, $ip);
    $q->execute();
    $q->close();
  } catch (Throwable $e) {
    error_log("logAuth error: " . $e->getMessage());
  }
}

function findStaff($conn, $username) {
  $q = $conn->prepare("SELECT id, username, password_hash, role, status, must_change_password FROM staff WHERE username = ? LIMIT 1");
  $q->bind_param("s", $username);
  $q->execute();
  $row = $q->get_result()->fetch_assoc();
  $q->close();
  return $row ?: null;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  $username = $_POST['username'] ?? '';
  $password = $_POST['password'] ?? '';

  $staff = findStaff($conn, $username);

  if ($staff && password_verify($password, $staff['password_hash']) && $staff['status'] === 'ACTIVE') {

    // Temporary password: do NOT log in yet. Force a password change first.
    if (!empty($staff['must_change_password'])) {
      session_regenerate_id(true);
      $_SESSION['pw_change_id'] = (int)$staff['id'];
      logAuth($conn, $username, 'LOGIN', 'MUST_CHANGE', (int)$staff['id']);
      header("Location: change_password.php");
      exit;
    }

    session_regenerate_id(true);
    $role = $staff['role'];                       // admin | officer | personnel
    $_SESSION['staff_ids'][$role] = (int)$staff['id'];
    unset($_SESSION['summary_from'], $_SESSION['auth_from']);   // forget old choices

    // Each role keeps its OWN session keys so logins never overwrite each other.
    if ($role === 'admin') {
      $_SESSION['admin_logged_in'] = true;
      $_SESSION['admin_username']  = $username;
      $_SESSION['last_role']       = 'admin';
      sess_start($conn, 'admin', $username);
      $redirect = 'admin_dashboard.php';

    } elseif ($role === 'officer') {
      $_SESSION['officer_logged_in'] = true;
      $_SESSION['officer_username']  = $username;
      $_SESSION['username']          = $username;   // kept for older pages
      $_SESSION['last_role']         = 'officer';
      sess_start($conn, 'officer', $username);
      $redirect = 'officer_dashboard.php';

    } else {                                       // personnel
      $_SESSION['security_logged_in'] = true;
      $_SESSION['security_username']  = $username;
      $_SESSION['username']           = $username;
      $_SESSION['last_role']          = 'security';
      sess_start($conn, 'security', $username);
      $redirect = 'dashboard.php';
    }

    logAuth($conn, $username, 'LOGIN', 'SUCCESS', (int)$staff['id']);
    header("Location: $redirect");
    exit;
  }

  // wrong username, wrong password, or inactive account (same message on purpose)
  logAuth($conn, $username, 'LOGIN', 'FAILED', $staff ? (int)$staff['id'] : null);
  $error = "Invalid username or password";
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login</title>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  width: 100%;
  height: 100%;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #fafbfd;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  color: #16233d;
  position: relative;
  overflow: hidden;
}

/* ===== SCHOOL PHOTO BACKGROUND (navy overlay + blur) ===== */
.background {
  position: fixed;
  inset: 0;
  z-index: 0;
}

.background::before {
  content: '';
  position: absolute;
  inset: -30px;
  background:
    linear-gradient(rgba(15,36,64,0.55), rgba(15,36,64,0.80)),
    url('background (1).jpg') center/cover no-repeat;
  filter: blur(8px);
  transform: scale(1.08);
}

.login-card {
  position: relative;
  z-index: 2;
  width: 360px;
  background: #ffffff;
  border: 1px solid #dce4ef;
  border-radius: 20px;
  padding: 40px 36px;
  box-shadow: 0 15px 40px rgba(15,36,64,0.25);
}

.brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  margin-bottom: 24px;
}

.brand img {
  width: 56px;
  height: 56px;
  border-radius: 14px;
  object-fit: cover;
  border: 1px solid #dce4ef;
}

.brand-name {
  font-size: 14px;
  font-weight: 600;
  color: #16233d;
  letter-spacing: 0.02em;
}

.login-title {
  font-size: 22px;
  font-weight: 600;
  color: #16233d;
  margin-bottom: 6px;
  text-align: center;
}

.login-sub {
  font-size: 13px;
  color: #8a9bb5;
  margin-bottom: 32px;
  text-align: center;
}

.error {
  font-size: 13px;
  color: #dc2626;
  background: #fdeaea;
  border: 1px solid #f6c6c6;
  border-radius: 10px;
  padding: 10px 14px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.field {
  margin-bottom: 16px;
}

.field label {
  display: block;
  font-size: 11px;
  font-weight: 500;
  color: #8a9bb5;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 8px;
}

.input-wrap {
  position: relative;
}

.input-wrap i {
  position: absolute;
  left: 14px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 16px;
  color: #a3b3cc;
  pointer-events: none;
}

.input-wrap input {
  width: 100%;
  padding: 11px 14px 11px 40px;
  border-radius: 10px;
  border: 1px solid #dce4ef;
  background: #f8fafc;
  color: #16233d;
  font-size: 14px;
  outline: none;
  transition: border-color 0.2s, background 0.2s;
}

.input-wrap input::placeholder {
  color: #a3b3cc;
}

.input-wrap input:focus {
  border-color: #1c3a5e;
  background: #ffffff;
}

/* PASSWORD TOGGLE */
.input-wrap.has-toggle input {
  padding-right: 44px;
}

.toggle-pw {
  position: absolute;
  top: 50%;
  right: 8px;
  transform: translateY(-50%);
  width: 30px;
  height: 30px;
  padding: 0;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: #8a9bb5;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: color 0.2s, background 0.2s;
}

.toggle-pw:hover {
  color: #1c3a5e;
  background: #eef2f8;
}

.toggle-pw:focus-visible {
  outline: 2px solid #1c3a5e;
  outline-offset: 1px;
}

.toggle-pw svg {
  width: 18px;
  height: 18px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

/* hidden password = closed (slashed) eye, visible password = open eye */
.toggle-pw .eye { display: none; }
.toggle-pw.showing .eye { display: block; }
.toggle-pw.showing .eye-off { display: none; }

.forgot-row {
  text-align: right;
  margin: -4px 0 4px;
}

.forgot-row a {
  font-size: 12px;
  color: #1c3a5e;
  text-decoration: none;
}

.forgot-row a:hover {
  text-decoration: underline;
}

.login-btn {
  width: 100%;
  margin-top: 8px;
  padding: 13px;
  border-radius: 11px;
  border: 1px solid #1c3a5e;
  background: #1c3a5e;
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  letter-spacing: 0.01em;
  transition: opacity 0.2s;
}

.login-btn:hover {
  opacity: 0.85;
}

.divider {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 20px 0 0;
}

.divider-line {
  flex: 1;
  height: 1px;
  background: #eef2f8;
}

.divider-text {
  font-size: 11px;
  color: #a3b3cc;
}

.role-hint {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}

.role-pill {
  flex: 1;
  padding: 8px 0;
  border-radius: 8px;
  background: #f4f7fb;
  border: 1px solid #dce4ef;
  text-align: center;
  font-size: 12px;
  color: #6b7a94;
}

.role-pill i {
  margin-right: 5px;
  font-size: 13px;
  vertical-align: -2px;
}
</style>
</head>

<body>

<div class="background"></div>

<div class="login-card">

  <div class="brand">
    <img src="logo.png" alt="Logo">
    <span class="brand-name"></span>
  </div>

  <div class="login-title">Welcome Back</div>
  <div class="login-sub">Sign in to your account</div>

  <?php if ($error): ?>
    <div class="error">
      <i class="ti ti-alert-circle"></i>
      <?= htmlspecialchars($error) ?>
    </div>
  <?php endif; ?>

  <form method="POST">

    <div class="field">
      <label>Username</label>

      <div class="input-wrap">
        <i class="ti ti-user"></i>

        <input
          type="text"
          name="username"
          placeholder="Enter your username"
          required
          autofocus
        >
      </div>
    </div>

    <div class="field">
      <label for="password">Password</label>

      <div class="input-wrap has-toggle">
        <i class="ti ti-lock"></i>

        <input
          type="password"
          id="password"
          name="password"
          placeholder="Enter your password"
          required
        >

        <button type="button" class="toggle-pw" id="togglePw" aria-label="Show password" title="Show password">
          <!-- open eye (password visible) -->
          <svg class="eye" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/>
            <circle cx="12" cy="12" r="3"/>
          </svg>
          <!-- closed eye (password hidden) -->
          <svg class="eye-off" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M2 12s3.6-7 10-7c2 0 3.8.7 5.3 1.6M22 12s-3.6 7-10 7c-2 0-3.8-.7-5.3-1.6"/>
            <path d="M9.9 9.9a3 3 0 004.2 4.2"/>
            <path d="M3 3l18 18"/>
          </svg>
        </button>
      </div>
    </div>

    <div class="forgot-row">
      <a href="forgot_password.php">Forgot password?</a>
    </div>

    <button type="submit" class="login-btn">
      Sign in
    </button>

  </form>

</div>

<script>
  var pwInput  = document.getElementById('password');
  var pwToggle = document.getElementById('togglePw');

  pwToggle.addEventListener('click', function () {
    var show = pwInput.type === 'password';
    pwInput.type = show ? 'text' : 'password';
    pwToggle.classList.toggle('showing', show);
    pwToggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    pwToggle.setAttribute('title', show ? 'Hide password' : 'Show password');
  });
</script>

</body>
</html>