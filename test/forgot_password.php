<?php
// Change these to your real admin contact details
$adminOffice = "Administrator's Office";
$adminPhone  = "0000-000-0000";
$adminEmail  = "admin@yourschool.edu";
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forgot Password</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#fafbfd; min-height:100vh; display:flex; justify-content:center; align-items:center; color:#16233d; padding:20px; }
.card { width:380px; max-width:100%; background:#fff; border:1px solid #dce4ef; border-radius:20px; padding:36px; box-shadow:0 15px 40px rgba(15,36,64,.15); }
h1 { font-size:20px; margin-bottom:6px; text-align:center; }
p.sub { font-size:13px; color:#8a9bb5; margin-bottom:24px; text-align:center; }
.contact { background:#f4f7fb; border:1px solid #dce4ef; border-radius:12px; padding:14px 16px; margin-bottom:20px; font-size:13px; line-height:1.7; }
.contact strong { display:block; margin-bottom:4px; }
ol { font-size:13px; color:#3c4a63; padding-left:18px; margin-bottom:24px; line-height:1.8; }
.btn { display:block; width:100%; text-align:center; text-decoration:none; padding:13px; border-radius:11px; border:1px solid #1c3a5e; background:#1c3a5e; color:#fff; font-size:14px; font-weight:600; }
.btn:hover { opacity:.85; }
</style>
</head>
<body>
<div class="card">
  <h1>Forgot your password?</h1>
  <p class="sub">Passwords can only be reset by the administrator.</p>

  <div class="contact">
    <strong>Contact the administrator</strong>
    <?= htmlspecialchars($adminOffice) ?><br>
    Phone: <?= htmlspecialchars($adminPhone) ?><br>
    Email: <?= htmlspecialchars($adminEmail) ?>
  </div>

  <ol>
    <li>Contact the administrator and confirm your identity.</li>
    <li>The administrator will give you a temporary password.</li>
    <li>Sign in with it, then choose your own new password.</li>
  </ol>

  <a href="login.php" class="btn">Back to Sign in</a>
</div>
</body>
</html>