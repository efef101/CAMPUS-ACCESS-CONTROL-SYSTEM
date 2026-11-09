<?php
session_start();
include 'db.php';

if (!isset($_SESSION['security_logged_in'])) {
  header("Location: login.php");
  exit;
}

header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

$logs = $conn->query("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10");
$users = $conn->query("SELECT * FROM users WHERE status='IN'");
$visitors = $conn->query("SELECT * FROM visitors WHERE status='IN'");
?>

<!DOCTYPE html>
<html>
<head>
<title>Security Dashboard</title>

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
  color: #7c8aa3;
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

/* CARDS */
.cards {
  display: flex;
  gap: 16px;
  margin-bottom: 24px;
}

.card {
  flex: 1;
  background: #ffffff;
  padding: 20px;
  border-radius: 14px;
  border: 1px solid #dce4ef;
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
}

.card small {
  font-size: 12px;
  color: #8a9bb5;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.card h2 {
  font-size: 32px;
  font-weight: 700;
  margin-top: 8px;
  color: #1c3a5e;
}

.card .icon {
  font-size: 22px;
  margin-bottom: 10px;
}

/* ACTION BUTTONS */
.actions {
  display: flex;
  gap: 12px;
  margin-bottom: 28px;
}

.actions a {
  text-decoration: none;
}

.btn-primary {
  padding: 11px 20px;
  border-radius: 10px;
  border: 1px solid #1c3a5e;
  background: #1c3a5e;
  color: #fff;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-primary:hover {
  opacity: 0.85;
}

.btn-secondary {
  padding: 11px 20px;
  border-radius: 10px;
  border: 1px solid #dce4ef;
  background: #ffffff;
  color: #1c3a5e;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: #eef3fa;
}

/* SECTIONS */
.sections {
  display: flex;
  gap: 16px;
  margin-bottom: 24px;
}

.section {
  flex: 1;
  background: #ffffff;
  border-radius: 14px;
  border: 1px solid #dce4ef;
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  padding: 20px;
}

.section-full {
  background: #ffffff;
  border-radius: 14px;
  border: 1px solid #dce4ef;
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  padding: 20px;
  margin-bottom: 24px;
}

.section h3, .section-full h3 {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 16px;
  color: #16233d;
}

/* TABLE */
table {
  width: 100%;
  border-collapse: collapse;
}

th {
  text-align: left;
  font-size: 11px;
  color: #96a6c0;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding-bottom: 10px;
}

td {
  padding: 10px 0;
  border-top: 1px solid #eef2f8;
  font-size: 13px;
  color: #3c4a63;
}

tr:hover td {
  color: #16233d;
}

.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
}

.badge-in {
  background: #e8f8ef;
  color: #16a34a;
}

.badge-out {
  background: #fdeaea;
  color: #dc2626;
}

.empty {
  color: #b7c3d6;
  font-size: 13px;
  padding: 12px 0;
}
</style>

</head>
<body>

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="logo">
    <img src="logo.png" alt="logo">
  </div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="dashboard.php" title="Dashboard">🏠</a>
  <a class="nav-item" href="scanner.html" title="Scanner">📷</a>
  <a class="nav-item" href="security_logs.php" title="Logs">📋</a>
  <a class="nav-item logout-item" href="logout.php" title="Logout">🚪</a>
</div>

<!-- MAIN -->
<div class="main">

  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <h1>Security Dashboard</h1>
      <p><?= date('l, F j, Y') ?></p>
    </div>
    <a href="logout.php" class="logout">Logout</a>
  </div>

  <!-- CARDS -->
  <div class="cards">
    <div class="card">
      <div class="icon">👤</div>
      <small>Campus Members Inside</small>
      <h2><?= $users->num_rows ?></h2>
    </div>
    <div class="card">
      <div class="icon">👨‍👨‍👦‍👦</div>
      <small>Visitors Inside</small>
      <h2><?= $visitors->num_rows ?></h2>
    </div>
    <div class="card">
      <div class="icon">📊</div>
      <small>Recent Logs</small>
      <h2><?= $logs->num_rows ?></h2>
    </div>
  </div>

  <!-- ACTIONS -->
  <div class="actions">
    <a href="scanner_hw.php">
      <button class="btn-primary">⛶ Start Scanning</button>
    </a>
    <a href="visitor_register.php">
      <button class="btn-secondary">Register Visitor</button>
    </a>
    <a href="security_logs.php">
      <button class="btn-secondary">📋 View All Logs</button>
    </a>
  </div>

  <!-- USERS + VISITORS -->
  <div class="sections">

    <div class="section">
      <h3>👤 Campus Members Inside</h3>
      <table>
        <tr><th>Name</th><th>Role</th></tr>
        <?php
          $users->data_seek(0);
          if ($users->num_rows > 0):
            while($row = $users->fetch_assoc()): ?>
          <tr>
            <td><?= htmlspecialchars($row['first_name']." ".$row['last_name']) ?></td>
            <td><?= htmlspecialchars($row['role']) ?></td>
          </tr>
        <?php endwhile; else: ?>
          <tr><td colspan="2" class="empty">No users inside</td></tr>
        <?php endif; ?>
      </table>
    </div>

    <div class="section">
      <h3>👨‍👩‍👦‍👦 Visitors Inside</h3>
      <table>
        <tr><th>Name</th><th>Purpose</th></tr>
        <?php
          $visitors->data_seek(0);
          if ($visitors->num_rows > 0):
            while($row = $visitors->fetch_assoc()): ?>
          <tr>
            <td><?= htmlspecialchars($row['name']) ?></td>
            <td><?= htmlspecialchars($row['purpose']) ?></td>
          </tr>
        <?php endwhile; else: ?>
          <tr><td colspan="2" class="empty">No visitors inside</td></tr>
        <?php endif; ?>
      </table>
    </div>

  </div>

  <!-- LOGS -->
  <div class="section-full">
    <h3>📋 Recent Logs</h3>
    <table>
      <tr><th>Name</th><th>Status</th><th>Time</th></tr>
      <?php
        $logs->data_seek(0);
        while($row = $logs->fetch_assoc()): ?>
      <tr>
        <td><?= htmlspecialchars($row['name']) ?></td>
        <td>
          <span class="badge <?= $row['status'] === 'IN' ? 'badge-in' : 'badge-out' ?>">
            <?= htmlspecialchars($row['status']) ?>
          </span>
        </td>
        <td><?= htmlspecialchars($row['timestamp']) ?></td>
      </tr>
      <?php endwhile; ?>
    </table>
  </div>

</div>

</body>
</html>