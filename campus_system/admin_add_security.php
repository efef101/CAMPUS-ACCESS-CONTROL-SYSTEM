<?php
include 'db.php';

$message = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  $first_name = trim($_POST['first_name']);
  $last_name  = trim($_POST['last_name']);
  $username   = trim($_POST['username']);
  $password   = password_hash($_POST['password'], PASSWORD_DEFAULT);
  $contact    = trim($_POST['contact_number']);
  $shift      = trim($_POST['shift_schedule']);

  // CHECK IF USERNAME EXISTS
  $check = $conn->prepare("SELECT id FROM security WHERE username = ?");
  $check->bind_param("s", $username);
  $check->execute();
  $check->store_result();

  if ($check->num_rows > 0) {

    $message = "❌ Username already exists.";

  } else {

    $stmt = $conn->prepare("
      INSERT INTO security
      (
        first_name,
        last_name,
        username,
        password,
        contact_number,
        shift_schedule,
        status
      )
      VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
    ");

    $stmt->bind_param(
      "ssssss",
      $first_name,
      $last_name,
      $username,
      $password,
      $contact,
      $shift
    );

    if ($stmt->execute()) {
      $message = "✅ Security account created successfully!";
    } else {
      $message = "❌ Error: " . $stmt->error;
    }
  }
}
?>

<!DOCTYPE html>
<html>
<head>
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

<img src="logo.png" class="bg-logo">

<div class="box">

  <h3>Create Security Account</h3>

  <p class="subtitle">
    Register and manage security personnel accounts.
  </p>

  <?php if($message): ?>
    <div class="message"><?= $message ?></div>
  <?php endif; ?>

  <form method="POST">

    <div class="row">

      <div class="form-group">
        <label>First Name</label>
        <input
          type="text"
          name="first_name"
          placeholder="Juan"
          required
        >
      </div>

      <div class="form-group">
        <label>Last Name</label>
        <input
          type="text"
          name="last_name"
          placeholder="Dela Cruz"
          required
        >
      </div>

    </div>

    <div class="form-group">
      <label>Contact Number</label>
      <input
        type="text"
        name="contact_number"
        placeholder="09XXXXXXXXX"
        required
      >
    </div>

    <div class="form-group">
      <label>Shift Schedule</label>
      <select name="shift_schedule" required>
        <option value="">Select Shift</option>
        <option value="Morning">Morning Shift</option>
        <option value="Afternoon">Afternoon Shift</option>
        <option value="Night">Night Shift</option>
      </select>
    </div>

    <div class="form-group">
      <label>Username</label>
      <input
        type="text"
        name="username"
        placeholder="Enter username"
        required
      >
    </div>

    <div class="form-group">
      <label>Password</label>
      <input
        type="password"
        name="password"
        placeholder="Enter password"
        required
      >
    </div>

    <button type="submit">
      Create Security Account
    </button>

  </form>

  <div class="back">
    <a href="admin_dashboard.php">← Back to Dashboard</a>
  </div>

</div>

</body>
</html>