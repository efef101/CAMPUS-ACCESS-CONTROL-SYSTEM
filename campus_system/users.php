<?php
include 'db.php';

/* MARK AS ALUMNI */
if(isset($_GET['alumni'])){

  $id = intval($_GET['alumni']);

  $stmt = $conn->prepare(
    "UPDATE users SET role='Alumni' WHERE id=?"
  );

  $stmt->bind_param("i", $id);
  $stmt->execute();

  header("Location: users.php");
  exit;
}

$result = $conn->query("SELECT * FROM users");
?>

<!DOCTYPE html>
<html>
<head>
<title>Registered Users</title>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jsbarcode/3.11.5/JsBarcode.all.min.js"></script>

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
  overflow-x: hidden;
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

.back-btn {
  text-decoration: none;
  padding: 8px 16px;
  border-radius: 8px;
  background: #ffffff;
  border: 1px solid #dce4ef;
  color: #3c5a80;
  font-size: 13px;
  transition: all 0.2s;
}

.back-btn:hover {
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

/* TABLE */
table {
  width: 100%;
  border-collapse: collapse;
}

th {
  text-align: left;
  padding: 16px 18px;
  font-size: 11px;
  color: #8a9bb5;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  border-bottom: 1px solid #eef2f8;
  background: #f4f7fb;
}

td {
  padding: 16px 18px;
  border-bottom: 1px solid #eef2f8;
  font-size: 13px;
  color: #3c4a63;
  vertical-align: middle;
}

tr:hover td {
  color: #16233d;
  background: #f7fafd;
}

/* ROLE BADGE */
.badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.student {
  background: #eef3fa;
  color: #1c3a5e;
}

.faculty {
  background: #f3ecfb;
  color: #7c3aed;
}

.staff {
  background: #e8f8ef;
  color: #16a34a;
}

.alumni {
  background: #fdf1d8;
  color: #d97706;
}

/* BARCODE */
.barcode-box {
  background: #fff;
  border-radius: 10px;
  padding: 10px;
  display: inline-flex;
  justify-content: center;
  align-items: center;
  border: 1px solid #eef2f8;
}

.barcode {
  max-width: 180px;
}

/* ACTION BUTTON */
.action-btn {
  display: inline-block;
  padding: 8px 14px;
  border-radius: 8px;
  text-decoration: none;
  font-size: 12px;
  font-weight: 600;
  background: #fdf1d8;
  color: #b4650a;
  border: 1px solid #f0d79a;
  transition: all 0.2s;
}

.action-btn:hover {
  background: #fbe6b8;
}

/* EMPTY */
.empty {
  text-align: center;
  padding: 40px;
  color: #b7c3d6;
}

/* RESPONSIVE */
@media(max-width:900px){

  .container{
    overflow-x:auto;
  }

  table{
    min-width:900px;
  }
}

</style>
</head>

<body>

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="logo"><img src="logo.png" alt="logo"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="admin_dashboard.php" title="Dashboard">🏠</a>
  <a class="nav-item active" href="users.php" title="Users">👤</a>
  <a class="nav-item" href="admin_add_security.php" title="Security Accounts">🔐</a>
  <a class="nav-item" href="logs.php" title="Logs">📋</a>
  <a class="nav-item logout-item" href="logout.php" title="Logout">🚪</a>
</div>

<!-- MAIN -->
<div class="main">

  <!-- HEADER -->
  <div class="header">

    <div class="header-left">
      <h1>Registered Users</h1>
      <p>Manage and view all registered campus members.</p>
    </div>

    <a href="admin_dashboard.php" class="back-btn">
      ← Back to Dashboard
    </a>

  </div>

  <!-- TABLE -->
  <div class="container">

  <table>

  <tr>
    <th>ID</th>
    <th>Name</th>
    <th>Role</th>
    <th>Barcode</th>
    <th>Action</th>
  </tr>

  <?php if($result->num_rows > 0): ?>

  <?php while($row = $result->fetch_assoc()): ?>

  <tr>

    <td>
      <?= htmlspecialchars($row['id_number']) ?>
    </td>

    <td>
      <?= htmlspecialchars($row['first_name'] . " " . $row['last_name']) ?>
    </td>

    <td>

      <span class="badge <?= strtolower($row['role']) ?>">
        <?= htmlspecialchars($row['role']) ?>
      </span>

    </td>

    <td>

      <div class="barcode-box">
        <svg
          class="barcode"
          data-code="<?= $row['id_number'] ?>"
        ></svg>
      </div>

    </td>

    <td>

      <?php if(strtolower($row['role']) !== 'alumni'): ?>

        <a
          class="action-btn"
          href="users.php?alumni=<?= $row['id'] ?>"
          onclick="return confirm('Convert this user to Alumni?')"
        >
          Mark as Alumni
        </a>

      <?php else: ?>

        <span style="color:#8a9bb5; font-size:12px;">
          Already Alumni
        </span>

      <?php endif; ?>

    </td>

  </tr>

  <?php endwhile; ?>

  <?php else: ?>

  <tr>
    <td colspan="5" class="empty">
      No registered users found.
    </td>
  </tr>

  <?php endif; ?>

  </table>

  </div>

</div>

<script>

document.addEventListener("DOMContentLoaded", function () {

  document.querySelectorAll(".barcode").forEach(function(el) {

    let code = el.getAttribute("data-code");

    if (code && /^[0-9]{1,8}$/.test(code)) {

      JsBarcode(el, code, {
        format: "CODE128",
        width: 2,
        height: 50,
        displayValue: true,
        background: "#ffffff",
        lineColor: "#000000"
      });

    } else {

      el.innerHTML = "Invalid ID";
    }
  });
});

</script>

</body>
</html>