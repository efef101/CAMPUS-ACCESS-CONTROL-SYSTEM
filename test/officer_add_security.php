<?php
session_start();
require_once 'auth.php';

// Officer only (same session check as officer_security.php)
if (empty($_SESSION['officer_logged_in'])) {
  header("Location: admin_login.php");
  exit;
}

header('Cache-Control: no-store');

$message = '';

// Allowed positions (whitelist - the server never trusts the dropdown value)
$positions = ['Security Personnel', 'Security Officer'];

$old = [
  'first_name' => '',
  'last_name'  => '',
  'username'   => '',
  'contact'    => '',
  'position'   => '',
];

if ($_SERVER["REQUEST_METHOD"] === "POST") {

  csrf_check();

  $old['first_name'] = trim($_POST['first_name'] ?? '');
  $old['last_name']  = trim($_POST['last_name'] ?? '');
  $old['username']   = trim($_POST['username'] ?? '');
  $old['contact']    = preg_replace('/[\s-]+/', '', trim($_POST['contact_number'] ?? ''));
  $old['position']   = trim($_POST['position'] ?? '');

  $first_name = $old['first_name'];
  $last_name  = $old['last_name'];
  $username   = $old['username'];
  $contact    = $old['contact'];
  $position   = $old['position'];

  if ($first_name === '' || mb_strlen($first_name) > 50 ||
      $last_name === ''  || mb_strlen($last_name) > 50) {

    $message = "❌ Enter a first and last name (up to 50 characters each).";

  } elseif (!preg_match('/^[A-Za-z0-9._-]{4,30}$/', $username)) {

    $message = "❌ Username must be 4 to 30 characters: letters, numbers, dot, dash or underscore.";

  } elseif (!preg_match('/^(09|\+639)\d{9}$/', $contact)) {

    $message = "❌ Enter a valid mobile number, for example 09XXXXXXXXX.";

  } elseif (!in_array($position, $positions, true)) {

    $message = "❌ Please select a valid position.";

  } else {

    $check = $conn->prepare("SELECT id FROM security WHERE username = ?");
    $check->bind_param("s", $username);
    $check->execute();
    $check->store_result();

    if ($check->num_rows > 0) {

      $message = "❌ Username already exists.";

    } else {

      // The system generates the first password; only its hash is stored
      $temp = generate_temp_password();
      $hash = password_hash($temp, PASSWORD_DEFAULT);

      $ok    = false;
      $errno = 0;

      try {
        $stmt = $conn->prepare("
          INSERT INTO security
          (first_name, last_name, username, `position`, password, contact_number, status, must_change_password)
          VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 1)
        ");
        $stmt->bind_param("ssssss", $first_name, $last_name, $username, $position, $hash, $contact);
        $ok    = $stmt->execute();
        $errno = $stmt->errno;
      } catch (mysqli_sql_exception $e) {
        $errno = (int)$e->getCode();
        error_log('Add security account failed: ' . $e->getMessage());
      }

      if ($ok) {
        // Show the password once, on Security Accounts (same as Reset Password)
        $_SESSION['flash_temp'] = [
          'username' => $username,
          'password' => $temp,
          'context'  => 'created',
        ];
        audit_log($conn, "Created security account: " . $username);

        header("Location: officer_security.php");
        exit;
      }

      $message = ($errno === 1062)
        ? "❌ Username already exists."
        : "❌ Could not create the account. Please try again.";
    }
  }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Add Security Account</title>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #fafbfd;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  overflow: hidden;
  color: #16233d;
}

/* BACKGROUND LOGO */
.bg-logo {
  position: absolute;
  width: 520px;
  opacity: 0.04;
  filter: blur(2px);
  z-index: 0;
}

/* CARD */
.box {
  position: relative;
  z-index: 1;
  width: 430px;
  max-height: 100vh;
  overflow-y: auto;
  padding: 34px;
  border-radius: 22px;
  background: #ffffff;
  border: 1px solid #dce4ef;
  box-shadow: 0 10px 40px rgba(22,58,94,0.12);
}

h3 {
  font-size: 24px;
  font-weight: 600;
  margin-bottom: 6px;
  color: #16233d;
}

.subtitle {
  font-size: 13px;
  color: #8a9bb5;
  margin-bottom: 24px;
}

/* MESSAGE */
.message {
  margin-bottom: 18px;
  padding: 12px;
  border-radius: 10px;
  font-size: 13px;
  background: #f4f7fb;
  border: 1px solid #dce4ef;
  color: #3c4a63;
}

.note {
  font-size: 12px;
  color: #6b7a94;
  background: #f4f7fb;
  border: 1px solid #dce4ef;
  border-radius: 10px;
  padding: 10px 12px;
  margin-bottom: 15px;
  line-height: 1.5;
}

/* FORM */
.form-group {
  margin-bottom: 15px;
}

label {
  display: block;
  font-size: 12px;
  margin-bottom: 6px;
  color: #6b7a94;
}

input,
select {
  width: 100%;
  padding: 13px 14px;
  outline: none;
  border-radius: 12px;
  background: #f8fafc;
  border: 1px solid #dce4ef;
  color: #16233d;
  font-size: 14px;
  transition: 0.2s;
}

input:focus,
select:focus {
  border-color: #1c3a5e;
  background: #ffffff;
}

input::placeholder {
  color: #a3b3cc;
}

select option {
  background: #ffffff;
  color: #16233d;
}

/* GRID */
.row {
  display: flex;
  gap: 12px;
}

.row .form-group {
  flex: 1;
}

/* BUTTON */
button {
  width: 100%;
  padding: 14px;
  margin-top: 12px;
  border: 1px solid #1c3a5e;
  border-radius: 12px;
  background: #1c3a5e;
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: 0.2s;
}

button:hover {
  opacity: 0.85;
}

/* BACK */
.back {
  margin-top: 18px;
  text-align: center;
}

.back a {
  text-decoration: none;
  font-size: 13px;
  color: #8a9bb5;
  transition: 0.2s;
}

.back a:hover {
  color: #1c3a5e;
}
</style>
</head>

<body>

<img src="logo.png" class="bg-logo" alt="">

<div class="box">

  <h3>Create Security Account</h3>

  <p class="subtitle">
    Register and manage security personnel accounts.
  </p>

  <?php if ($message): ?>
    <div class="message"><?= htmlspecialchars($message) ?></div>
  <?php endif; ?>

  <form method="POST" autocomplete="off">

    <input type="hidden" name="csrf" value="<?= htmlspecialchars(csrf_token()) ?>">

    <div class="row">

      <div class="form-group">
        <label for="first_name">First Name</label>
        <input
          type="text"
          id="first_name"
          name="first_name"
          placeholder="Juan"
          maxlength="50"
          value="<?= htmlspecialchars($old['first_name']) ?>"
          required
        >
      </div>

      <div class="form-group">
        <label for="last_name">Last Name</label>
        <input
          type="text"
          id="last_name"
          name="last_name"
          placeholder="Dela Cruz"
          maxlength="50"
          value="<?= htmlspecialchars($old['last_name']) ?>"
          required
        >
      </div>

    </div>

    <div class="form-group">
      <label for="position">Position</label>
      <select id="position" name="position" required>
        <option value="" disabled <?= $old['position'] === '' ? 'selected' : '' ?>>Select position</option>
        <?php foreach ($positions as $p): ?>
          <option value="<?= htmlspecialchars($p) ?>" <?= $old['position'] === $p ? 'selected' : '' ?>>
            <?= htmlspecialchars($p) ?>
          </option>
        <?php endforeach; ?>
      </select>
    </div>

    <div class="form-group">
      <label for="contact_number">Contact Number</label>
      <input
        type="text"
        id="contact_number"
        name="contact_number"
        placeholder="09XXXXXXXXX"
        maxlength="14"
        value="<?= htmlspecialchars($old['contact']) ?>"
        required
      >
    </div>

    <div class="form-group">
      <label for="username">Username</label>
      <input
        type="text"
        id="username"
        name="username"
        placeholder="Enter username"
        maxlength="30"
        pattern="[A-Za-z0-9._\-]{4,30}"
        title="4 to 30 characters: letters, numbers, dot, dash or underscore"
        value="<?= htmlspecialchars($old['username']) ?>"
        required
      >
    </div>

    <div class="note">
      A temporary password is generated automatically when you create the account.
      You will see it once on the Security Accounts page. The user must change it the first time they sign in.
    </div>

    <button type="submit">
      Create Security Account
    </button>

  </form>

  <div class="back">
    <a href="officer_dashboard.php">Back to Dashboard</a>
  </div>

</div>

</body>
</html>