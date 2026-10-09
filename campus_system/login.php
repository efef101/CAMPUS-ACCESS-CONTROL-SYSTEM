<?php
session_start();
include 'db.php';

$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  $username = $_POST['username'] ?? '';
  $password = $_POST['password'] ?? '';

  // Check security table first
  $stmt = $conn->prepare("SELECT * FROM security WHERE username=?");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $result = $stmt->get_result();

  if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();

    if (password_verify($password, $user['password'])) {
      $_SESSION['security_logged_in'] = true;
      $_SESSION['username'] = $username;

      header("Location: dashboard.php");
      exit;
    }
  }

  // Check admin table
  $stmt2 = $conn->prepare("SELECT * FROM admin WHERE username=?");
  $stmt2->bind_param("s", $username);
  $stmt2->execute();
  $result2 = $stmt2->get_result();

  if ($result2->num_rows === 1) {
    $admin = $result2->fetch_assoc();

    if (password_verify($password, $admin['password'])) {
      $_SESSION['admin_logged_in'] = true;
      $_SESSION['admin_username'] = $username;

      header("Location: admin_dashboard.php");
      exit;
    }
  }

  $error = "Invalid username or password";
}
?>

<!DOCTYPE html>
<html>
<head>
<title>Login</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #fafbfd;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  color: #16233d;
}

.login-card {
  width: 360px;
  background: #ffffff;
  border: 1px solid #dce4ef;
  border-radius: 20px;
  padding: 40px 36px;
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
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

<div class="login-card">

  <div class="brand">
    <img src="logo.png" alt="Logo">
    <span class="brand-name"></span>
  </div>

  <div class="login-title">Welcome back</div>
  <div class="login-sub">Sign in to access your dashboard</div>

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
        <input type="text" name="username" placeholder="Enter your username" required autofocus>
      </div>
    </div>

    <div class="field">
      <label>Password</label>
      <div class="input-wrap">
        <i class="ti ti-lock"></i>
        <input type="password" name="password" placeholder="Enter your password" required>
      </div>
    </div>

    <button type="submit" class="login-btn">Sign in</button>
  </form>

  <div class="divider">
    <div class="divider-line"></div>
    <span class="divider-text">CACS</span>
    <div class="divider-line"></div>
  </div>

  <div class="role-hint">
    <div class="role-pill"><i class="ti ti-shield-check"></i>Security</div>
    <div class="role-pill"><i class="ti ti-settings"></i>Admin</div>
  </div>

</div>

</body>
</html>