<?php
session_start();
include 'db.php';

// Only reachable after login.php verified a temporary password
if (empty($_SESSION['pw_change_id'])) {
  header("Location: login.php");
  exit;
}

$id = (int)$_SESSION['pw_change_id'];
$error = '';

$q = $conn->prepare("SELECT username, position, password, status FROM security WHERE id = ?");
$q->bind_param("i", $id);
$q->execute();
$user = $q->get_result()->fetch_assoc();

if (!$user || $user['status'] !== 'ACTIVE') {
  unset($_SESSION['pw_change_id']);
  header("Location: login.php");
  exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $new     = $_POST['new_password'] ?? '';
  $confirm = $_POST['confirm_password'] ?? '';

  if (strlen($new) < 8) {
    $error = "Password must be at least 8 characters.";
  } elseif (!preg_match('/[A-Z]/', $new)) {
    $error = "Password must contain at least one uppercase letter.";
  } elseif (!preg_match('/[0-9]/', $new)) {
    $error = "Password must contain at least one number.";
  } elseif (!preg_match('/[^A-Za-z0-9\s]/', $new)) {
    $error = "Password must contain at least one special character (for example ! @ # $ % &).";
  } elseif ($new !== $confirm) {
    $error = "Passwords do not match.";
  } elseif (password_verify($new, $user['password'])) {
    $error = "Choose a different password from the temporary one.";
  } else {
    $hash = password_hash($new, PASSWORD_DEFAULT);
    $upd = $conn->prepare("UPDATE security SET password = ?, must_change_password = 0 WHERE id = ?");
    $upd->bind_param("si", $hash, $id);
    $upd->execute();

    // Now complete the login, same as login.php does
    session_regenerate_id(true);
    unset($_SESSION['pw_change_id']);
    $username = $user['username'];

    if (($user['position'] ?? '') === 'Security Officer') {
      $_SESSION['officer_logged_in'] = true;
      $_SESSION['officer_username']  = $username;
      $_SESSION['username']          = $username;
      $redirect = 'officer_dashboard.php';
    } else {
      $_SESSION['security_logged_in'] = true;
      $_SESSION['security_username']  = $username;
      $_SESSION['username']           = $username;
      $redirect = 'dashboard.php';
    }

    header("Location: $redirect");
    exit;
  }
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Change Password</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#fafbfd; min-height:100vh; display:flex; justify-content:center; align-items:center; color:#16233d; }
.card { width:360px; background:#fff; border:1px solid #dce4ef; border-radius:20px; padding:36px; box-shadow:0 15px 40px rgba(15,36,64,.15); }
h1 { font-size:20px; margin-bottom:6px; text-align:center; }
p.sub { font-size:13px; color:#8a9bb5; margin-bottom:24px; text-align:center; }
.error { font-size:13px; color:#dc2626; background:#fdeaea; border:1px solid #f6c6c6; border-radius:10px; padding:10px 14px; margin-bottom:16px; }
label { display:block; font-size:11px; color:#8a9bb5; text-transform:uppercase; letter-spacing:.08em; margin-bottom:8px; }
input { width:100%; padding:11px 14px; border-radius:10px; border:1px solid #dce4ef; background:#f8fafc; font-size:14px; margin-bottom:16px; outline:none; }
input:focus { border-color:#1c3a5e; background:#fff; }
.rules { font-size:12px; color:#6b7a94; background:#f4f7fb; border:1px solid #dce4ef; border-radius:10px; padding:10px 14px 10px 30px; margin:-6px 0 16px; line-height:1.7; }
button { width:100%; padding:13px; border-radius:11px; border:1px solid #1c3a5e; background:#1c3a5e; color:#fff; font-size:14px; font-weight:600; cursor:pointer; }
button:hover { opacity:.85; }
</style>
</head>
<body>
<div class="card">
  <h1>Set a New Password</h1>
  <p class="sub">Your password was reset by the admin. Choose your own to continue.</p>

  <?php if ($error): ?>
    <div class="error"><?= htmlspecialchars($error) ?></div>
  <?php endif; ?>

  <form method="POST">
    <label for="new_password">New password</label>
    <input type="password" id="new_password" name="new_password" required minlength="8" autofocus>

    <ul class="rules">
      <li>At least 8 characters</li>
      <li>At least one uppercase letter (A-Z)</li>
      <li>At least one number (0-9)</li>
      <li>At least one special character (! @ # $ % &amp; ...)</li>
    </ul>

    <label for="confirm_password">Confirm new password</label>
    <input type="password" id="confirm_password" name="confirm_password" required minlength="8">

    <button type="submit">Save and continue</button>
  </form>
</div>
</body>
</html>