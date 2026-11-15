<?php
session_start();
include 'db.php';

$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  $username = $_POST['username'] ?? '';
  $password = $_POST['password'] ?? '';

  $stmt = $conn->prepare("SELECT * FROM admin WHERE username=?");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $result = $stmt->get_result();

  if ($result->num_rows === 1) {
    $admin = $result->fetch_assoc();

    if (password_verify($password, $admin['password'])) {
      $_SESSION['admin_logged_in'] = true;
      $_SESSION['admin_username'] = $username;

      header("Location: admin_dashboard.php");
      exit;
    }
  }

  $error = "Invalid admin credentials";
}
?>

<!DOCTYPE html>
<html>
<head>
<title>Admin Login</title>

<style>
body {
  margin: 0;
  font-family: sans-serif;
  background: #f2f2f2;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
}

.box {
  background: white;
  padding: 30px;
  border-radius: 10px;
  width: 300px;
}

input, button {
  width: 100%;
  padding: 10px;
  margin-top: 10px;
}

button {
  background: black;
  color: white;
  border: none;
  cursor: pointer;
}
</style>
</head>

<body>

<div class="box">
  <h2>Admin Login</h2>

  <?php if($error): ?>
    <p style="color:red;"><?= $error ?></p>
  <?php endif; ?>

  <form method="POST">
    <input type="text" name="username" placeholder="Admin Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
</div>

</body>
</html>