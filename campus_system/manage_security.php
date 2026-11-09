<?php
include 'db.php';
session_start();

if (!isset($_SESSION['admin_logged_in'])) {
  header("Location: login.php");
  exit;
}

// DELETE ACCOUNT
if (isset($_GET['delete'])) {

  $id = intval($_GET['delete']);

  $delete = $conn->prepare("DELETE FROM security WHERE id = ?");
  $delete->bind_param("i", $id);
  $delete->execute();

  header("Location: manage_security.php");
  exit;
}

// TOGGLE STATUS
if (isset($_GET['toggle'])) {

  $id = intval($_GET['toggle']);

  $get = $conn->prepare("SELECT status FROM security WHERE id = ?");
  $get->bind_param("i", $id);
  $get->execute();

  $result = $get->get_result();

  if ($result->num_rows > 0) {

    $row = $result->fetch_assoc();

    $newStatus = ($row['status'] === 'ACTIVE')
      ? 'INACTIVE'
      : 'ACTIVE';

    $update = $conn->prepare("UPDATE security SET status = ? WHERE id = ?");
    $update->bind_param("si", $newStatus, $id);
    $update->execute();
  }

  header("Location: manage_security.php");
  exit;
}

$security = $conn->query("SELECT * FROM security ORDER BY created_at DESC");
?>

<!DOCTYPE html>
<html>
<head>
<title>Manage Security Accounts</title>

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
  position: relative;
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

/* Tooltip */
.nav-item::after {
  content: attr(title);
  position: absolute;
  left: 58px;
  background: #16233d;
  color: #fff;
  font-size: 11px;
  padding: 4px 10px;
  border-radius: 6px;
  white-space: nowrap;
  border: 1px solid rgba(255,255,255,0.1);
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.15s;
  z-index: 100;
}

.nav-item:hover::after {
  opacity: 1;
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

.header h1 {
  font-size: 22px;
  font-weight: 600;
  color: #16233d;
}

.header a {
  text-decoration: none;
  color: #3c5a80;
  font-size: 13px;
  padding: 8px 16px;
  border-radius: 8px;
  border: 1px solid #dce4ef;
  background: #ffffff;
  transition: all 0.2s;
}

.header a:hover {
  background: #eef3fa;
  color: #16233d;
}

/* CONTAINER */
.container {
  background: #ffffff;
  border-radius: 14px;
  border: 1px solid #dce4ef;
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  overflow: hidden;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th {
  text-align: left;
  padding: 16px 18px;
  font-size: 11px;
  color: #8a9bb5;
  border-bottom: 1px solid #eef2f8;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  background: #f4f7fb;
}

td {
  padding: 16px 18px;
  font-size: 13px;
  border-bottom: 1px solid #eef2f8;
  color: #3c4a63;
}

tr:hover td {
  color: #16233d;
  background: #f7fafd;
}

.badge {
  padding: 3px 12px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
}

.active {
  background: #e8f8ef;
  color: #16a34a;
}

.inactive {
  background: #fdeaea;
  color: #dc2626;
}

.actions {
  display: flex;
  gap: 10px;
}

.btn {
  text-decoration: none;
  padding: 8px 14px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 600;
  transition: all 0.2s;
}

.btn-toggle {
  background: #eef3fa;
  color: #1c3a5e;
  border: 1px solid #c7d7ec;
}

.btn-toggle:hover {
  background: #dfeaf7;
}

.btn-delete {
  background: #fdeaea;
  color: #dc2626;
  border: 1px solid #f6c6c6;
}

.btn-delete:hover {
  background: #fad8d8;
}

.empty {
  text-align: center;
  padding: 30px;
  color: #b7c3d6;
}
</style>
</head>

<body>

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="logo"><img src="logo.png" alt="logo"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="admin_dashboard.php" title="Dashboard">🏠</a>
  <a class="nav-item" href="users.php" title="Users">👤</a>
  <a class="nav-item active" href="admin_add_security.php" title="Security Accounts">🔐</a>
  <a class="nav-item" href="logs.php" title="Logs">📋</a>
  <a class="nav-item logout-item" href="logout.php" title="Logout">🚪</a>
</div>

<!-- MAIN -->
<div class="main">

  <div class="header">
    <h1>Manage Security Accounts</h1>

    <a href="admin_dashboard.php">
      ← Back to Dashboard
    </a>
  </div>

  <div class="container">

  <table>

  <tr>
    <th>Name</th>
    <th>Username</th>
    <th>Contact</th>
    <th>Shift</th>
    <th>Status</th>
    <th>Created</th>
    <th>Actions</th>
  </tr>

  <?php if($security->num_rows > 0): ?>

    <?php while($row = $security->fetch_assoc()): ?>

    <tr>

      <td>
        <?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?>
      </td>

      <td>
        <?= htmlspecialchars($row['username']) ?>
      </td>

      <td>
        <?= htmlspecialchars($row['contact_number']) ?>
      </td>

      <td>
        <?= htmlspecialchars($row['shift_schedule']) ?>
      </td>

      <td>

        <span class="badge <?= strtolower($row['status']) ?>">
          <?= htmlspecialchars($row['status']) ?>
        </span>

      </td>

      <td>
        <?= htmlspecialchars($row['created_at']) ?>
      </td>

      <td>

        <div class="actions">

          <a
            class="btn btn-toggle"
            href="manage_security.php?toggle=<?= $row['id'] ?>"
          >
            Toggle Status
          </a>

          <a
            class="btn btn-delete"
            href="manage_security.php?delete=<?= $row['id'] ?>"
            onclick="return confirm('Delete this account?')"
          >
            Delete
          </a>

        </div>

      </td>

    </tr>

    <?php endwhile; ?>

  <?php else: ?>

  <tr>
    <td colspan="7" class="empty">
      No security accounts found.
    </td>
  </tr>

  <?php endif; ?>

  </table>

  </div>

</div>

</body>
</html>