<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
include 'db.php';

$success = '';
$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {

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
      $error = "Error: " . $stmt->error;
    }
  }
}
?>

<!DOCTYPE html>
<html>
<head>
<title>Register Visitor</title>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #fafbfd;
  min-height: 100vh;
  display: flex;
  color: #16233d;
}

/* SIDEBAR */
.sidebar {
  width: 80px;
  background: linear-gradient(180deg, #1c3a5e, #0f2440);
  border-right: 1px solid #0f2440;
  height: 100vh;
  position: sticky;
  top: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 24px 0;
  gap: 12px;
}

.sidebar .logo img {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  object-fit: cover;
  border: 1px solid rgba(255,255,255,0.25);
}

.sidebar-divider {
  width: 40px;
  height: 1px;
  background: rgba(255,255,255,0.12);
  margin: 4px 0;
}

.sidebar .nav-item {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.12);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  cursor: pointer;
  transition: background 0.2s;
  text-decoration: none;
}

.sidebar .nav-item:hover {
  background: rgba(255,255,255,0.16);
}

.sidebar .nav-item.active {
  background: rgba(255,255,255,0.22);
  border-color: rgba(255,255,255,0.35);
}

.sidebar .logout-item {
  margin-top: auto;
}

/* MAIN */
.main {
  flex: 1;
  padding: 32px;
  overflow-y: auto;
}

/* HEADER */
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 28px;
}

.header-left h1 {
  font-size: 22px;
  font-weight: 600;
  color: #16233d;
}

.header-left p {
  font-size: 13px;
  color: #8a9bb5;
  margin-top: 4px;
}

.logout {
  font-size: 13px;
  color: #3c5a80;
  text-decoration: none;
  padding: 8px 16px;
  border-radius: 8px;
  border: 1px solid #dce4ef;
  background: #ffffff;
  transition: all 0.2s;
}

.logout:hover {
  background: #eef3fa;
  color: #16233d;
}

/* FORM CARD */
.form-card {
  background: #ffffff;
  border-radius: 14px;
  border: 1px solid #dce4ef;
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  padding: 28px;
  max-width: 520px;
}

.form-card h3 {
  font-size: 14px;
  font-weight: 600;
  color: #16233d;
  margin-bottom: 20px;
}

/* FORM FIELDS */
.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  font-size: 11px;
  font-weight: 600;
  color: #8a9bb5;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 6px;
}

.form-group input,
.form-group select {
  width: 100%;
  padding: 10px 14px;
  background: #f8fafc;
  border: 1px solid #dce4ef;
  border-radius: 10px;
  color: #16233d;
  font-size: 13px;
  outline: none;
  transition: border-color 0.2s, background 0.2s;
  font-family: inherit;
}

.form-group input::placeholder {
  color: #a3b3cc;
}

.form-group input:focus {
  border-color: #1c3a5e;
  background: #ffffff;
}

/* BUTTONS */
.btn-primary {
  padding: 11px 24px;
  border-radius: 10px;
  border: 1px solid #1c3a5e;
  background: #1c3a5e;
  color: #fff;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
  margin-top: 4px;
}

.btn-primary:hover {
  opacity: 0.85;
}

/* ALERTS */
.alert {
  padding: 12px 16px;
  border-radius: 10px;
  font-size: 13px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.alert-success {
  background: #e8f8ef;
  border: 1px solid #bdeccf;
  color: #16a34a;
}

.alert-error {
  background: #fdeaea;
  border: 1px solid #f6c6c6;
  color: #dc2626;
}
</style>

</head>
<body>

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="logo">
    <img src="logo.jpg" alt="logo">
  </div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="dashboard.php" title="Dashboard">🏠</a>
  <a class="nav-item" href="scanner.html" title="Scanner">📷</a>
  <a class="nav-item" href="logs.php" title="Logs">📋</a>
  <a class="nav-item active" href="visitor_register.php" title="Register Visitor">🪪</a>
  <a class="nav-item" href="register.html" title="Register User">➕</a>
  <a class="nav-item logout-item" href="logout.php" title="Logout">🚪</a>
</div>

<!-- MAIN -->
<div class="main">

  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <h1>Register Visitor</h1>
      <p><?= date('l, F j, Y') ?></p>
    </div>
    <a href="logout.php" class="logout">Logout</a>
  </div>

  <!-- ALERTS -->
  <?php if ($success): ?>
    <div class="alert alert-success">✅ <?= htmlspecialchars($success) ?></div>
  <?php endif; ?>
  <?php if ($error): ?>
    <div class="alert alert-error">❌ <?= htmlspecialchars($error) ?></div>
  <?php endif; ?>

  <!-- FORM -->
  <div class="form-card">
    <h3>🪪 Visitor Details</h3>
    <form method="POST">

      <div class="form-group">
        <label>QR Code</label>
        <input type="text" name="qr_code" placeholder="Scan or enter QR code" required>
      </div>

      <div class="form-group">
        <label>Visitor Name</label>
        <input type="text" name="name" placeholder="Full name" required>
      </div>

      <div class="form-group">
        <label>Purpose</label>
        <input type="text" name="purpose" placeholder="Purpose of visit" required>
      </div>

      <div class="form-group">
        <label>Destination</label>
        <input type="text" name="destination" placeholder="Where are they going?" required>
      </div>

      <button type="submit" class="btn-primary">Register Visitor</button>

    </form>
  </div>

</div>

</body>
</html>