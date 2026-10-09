<?php
include 'db.php';

function renderResult($user, $statusMessage) {

  $imgSrc = $user['face_image'];
  if (!str_starts_with($imgSrc, 'data:image')) {
    $imgSrc = 'data:image/jpeg;base64,' . $imgSrc;
  }

  $name       = htmlspecialchars($user['first_name'] . ' ' . $user['last_name']);
  $id_number  = htmlspecialchars($user['id_number']);
  $role       = htmlspecialchars($user['role']);
  $course     = htmlspecialchars($user['course']);
  $department = htmlspecialchars($user['department']);
  $statusColor = str_starts_with($statusMessage, '✅') ? '#16a34a' : '#dc2626';

  echo <<<HTML
  <!DOCTYPE html>
  <html>
  <head>
    <title>Verification Result</title>
    <style>
      * { box-sizing: border-box; }
      body {
        margin: 0;
        height: 100vh;
        overflow: hidden;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: #fafbfd;
        display: flex;
        justify-content: center;
        align-items: center;
      }
      .container {
        width: 360px;
        padding: 30px;
        background: #ffffff;
        border-radius: 18px;
        border: 1px solid #dce4ef;
        box-shadow: 0 1px 3px rgba(22,58,94,0.05);
        text-align: center;
        color: #16233d;
      }
      h2 { font-size: 18px; font-weight: 600; margin-bottom: 16px; color: #16233d; }
      img {
        width: 120px;
        height: 120px;
        border-radius: 10px;
        object-fit: cover;
        margin-bottom: 10px;
        border: 1px solid #dce4ef;
      }
      .info {
        font-size: 14px;
        color: #3c4a63;
        text-align: left;
        margin-top: 10px;
        line-height: 1.8;
      }
      .info strong { color: #16233d; }
      .status { margin-top: 12px; font-weight: 600; color: $statusColor; }
      .back { margin-top: 15px; }
      .back a { text-decoration: none; font-size: 13px; color: #8a9bb5; }
      .back a:hover { color: #1c3a5e; }
    </style>
  </head>
  <body>
  <div class='container'>
    <h2>Verification Result</h2>
    <img src="$imgSrc" />
    <div class='info'>
      <strong>Name:</strong> $name<br>
      <strong>ID:</strong> $id_number<br>
      <strong>Role:</strong> $role<br>
      <strong>Course:</strong> $course<br>
      <strong>Department:</strong> $department
    </div>
    <div class='status'>$statusMessage</div>
    <div class='back'><a href='dashboard.php'>← Back to Dashboard</a></div>
  </div>
  </body>
  </html>
HTML;
}

// ===== INPUT =====
$code = trim($_POST['code'] ?? $_POST['barcode'] ?? '');
$descriptorJson = $_POST['face_descriptor'] ?? '';

if ($code === '') {
  echo "Missing code.";
  exit;
}

// ===== CHECK VISITORS TABLE FIRST =====
$stmt = $conn->prepare("SELECT * FROM visitors WHERE qr_code = ?");
$stmt->bind_param("s", $code);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
  $visitor = $result->fetch_assoc();

  // Toggle IN/OUT
  $newStatus = ($visitor['status'] === 'IN') ? 'OUT' : 'IN';

  $update = $conn->prepare("UPDATE visitors SET status = ? WHERE id = ?");
  $update->bind_param("si", $newStatus, $visitor['id']);
  $update->execute();

  $visitorName = $visitor['name'];
  $type = ($newStatus === 'IN') ? 'ENTRY' : 'EXIT';

  $dupCheck = $conn->prepare("SELECT id FROM logs WHERE id_number = ? AND timestamp >= NOW() - INTERVAL 5 SECOND");
  $dupCheck->bind_param("s", $visitor['id']);
  $dupCheck->execute();
  if ($dupCheck->get_result()->num_rows === 0) {
  $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
  $role = 'Visitor';
  $log->bind_param("sssss", $visitor['id'], $visitorName, $role, $newStatus, $type);
  $log->execute();
}

  $name        = htmlspecialchars($visitor['name']);
  $purpose     = htmlspecialchars($visitor['purpose']);
  $destination = htmlspecialchars($visitor['destination']);

  echo <<<HTML
  <!DOCTYPE html>
  <html>
  <head>
    <title>Visitor Verified</title>
    <style>
      * { box-sizing: border-box; }
      body {
        margin: 0; height: 100vh; overflow: hidden;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: #fafbfd;
        display: flex; justify-content: center; align-items: center;
      }
      .container {
        width: 360px; padding: 30px;
        background: #ffffff;
        border-radius: 18px;
        border: 1px solid #dce4ef;
        box-shadow: 0 1px 3px rgba(22,58,94,0.05);
        text-align: center; color: #16233d;
      }
      h2 { font-size: 18px; font-weight: 600; margin-bottom: 16px; color: #16233d; }
      .info {
        font-size: 14px; color: #3c4a63;
        text-align: left; margin-top: 10px; line-height: 1.8;
      }
      .info strong { color: #16233d; }
      .status { margin-top: 12px; font-weight: 600; color: #16a34a; }
      .back { margin-top: 15px; }
      .back a { text-decoration: none; font-size: 13px; color: #8a9bb5; }
      .back a:hover { color: #1c3a5e; }
    </style>
  </head>
  <body>
  <div class='container'>
    <h2>Visitor Verified</h2>
    <div class='info'>
      <strong>Name:</strong> $name<br>
      <strong>Purpose:</strong> $purpose<br>
      <strong>Destination:</strong> $destination
    </div>
    <div class='status'>✅ $newStatus SUCCESS</div>
    <div class='back'><a href='dashboard.php'>← Back to Dashboard</a></div>
  </div>
  </body>
  </html>
HTML;
  exit;
}

// ===== CHECK USERS TABLE =====
$stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
$stmt->bind_param("s", $code);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
  echo "User not found.";
  exit;
}

$user = $result->fetch_assoc();

// ===== BARCODE ONLY — no face descriptor sent =====
if ($descriptorJson === '') {

  $newStatus = ($user['status'] === 'IN') ? 'OUT' : 'IN';

  $update = $conn->prepare("UPDATE users SET status=? WHERE id_number=?");
  $update->bind_param("ss", $newStatus, $code);
  $update->execute();

  $name      = $user['first_name'] . " " . $user['last_name'];
  $id_number = $user['id_number'];
  $role      = $user['role'];
  $type      = ($newStatus === 'IN') ? 'ENTRY' : 'EXIT';

  $dupCheck = $conn->prepare("SELECT id FROM logs WHERE id_number = ? AND timestamp >= NOW() - INTERVAL 5 SECOND");
  $dupCheck->bind_param("s", $id_number);
  $dupCheck->execute();
  if ($dupCheck->get_result()->num_rows === 0) {
    $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
    $log->bind_param("sssss", $id_number, $name, $role, $newStatus, $type);
    $log->execute();
  }

  renderResult($user, "✅ $newStatus SUCCESS");
  exit;
}

// ===== FACE MATCH — descriptor was sent =====
$descriptor = json_decode($descriptorJson, true);
$stored     = json_decode($user['face_descriptor'], true);

if (!is_array($descriptor) || !is_array($stored) || count($descriptor) !== 128 || count($stored) !== 128) {
  renderResult($user, "❌ Face data invalid. Please re-register.");
  exit;
}

$distance = 0.0;
for ($i = 0; $i < 128; $i++) {
  $diff = $descriptor[$i] - $stored[$i];
  $distance += $diff * $diff;
}
$distance = sqrt($distance);

if ($distance <= 0.7) {

  $newStatus = ($user['status'] === 'IN') ? 'OUT' : 'IN';

  $update = $conn->prepare("UPDATE users SET status=? WHERE id_number=?");
  $update->bind_param("ss", $newStatus, $code);
  $update->execute();

  $name      = $user['first_name'] . " " . $user['last_name'];
  $id_number = $user['id_number'];
  $role      = $user['role'];
  $type      = ($newStatus === 'IN') ? 'ENTRY' : 'EXIT';

  $dupCheck = $conn->prepare("SELECT id FROM logs WHERE id_number = ? AND timestamp >= NOW() - INTERVAL 5 SECOND");
  $dupCheck->bind_param("s", $id_number);
  $dupCheck->execute();
  if ($dupCheck->get_result()->num_rows === 0) {
    $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
    $log->bind_param("sssss", $id_number, $name, $role, $newStatus, $type);
    $log->execute();
  }

  renderResult($user, "✅ $newStatus SUCCESS");
  exit;
}

// FAILED
renderResult($user, "❌ FACE NOT MATCHED");
?>