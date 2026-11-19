<?php
session_start();
include 'db.php';

$error = '';
$username = '';

// One row in auth_logs. A logging problem must never stop someone from logging in.
function logAuth($conn, $username, $action, $status, $staffId = null) {
  try {
    $username = substr((string)$username, 0, 100);
    $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);   // REMOTE_ADDR only: headers can be faked
    $q = $conn->prepare("INSERT INTO auth_logs (staff_id, username_snapshot, action, status, ip_address) VALUES (?, ?, ?, ?, ?)");
    $q->bind_param("issss", $staffId, $username, $action, $status, $ip);
    $q->execute();
    $q->close();
  } catch (Throwable $e) {
    error_log("logAuth error: " . $e->getMessage());
  }
}

function findStaff($conn, $username) {
  $q = $conn->prepare("SELECT id, username, password_hash, role, status, must_change_password FROM staff WHERE username = ? LIMIT 1");
  $q->bind_param("s", $username);
  $q->execute();
  $row = $q->get_result()->fetch_assoc();
  $q->close();
  return $row ?: null;
}

// Close only the session row left by THIS browser (its old session id, before
// session_regenerate_id). Sessions on the account's other devices stay logged in;
// the Active Sessions page groups them so the account is shown only once.
function closeOldSessions($conn, $username, $oldSid) {
  if ($oldSid === '') return;
  try {
    $like = $oldSid . '|%';
    $q = $conn->prepare("UPDATE security_sessions
                         SET status = 'logged_out', logout_time = NOW()
                         WHERE username_snapshot = ? AND session_id LIKE ? AND status = 'active'");
    $q->bind_param("ss", $username, $like);
    $q->execute();
    $q->close();
  } catch (Throwable $e) {
    error_log("closeOldSessions error: " . $e->getMessage());
  }
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  $username = $_POST['username'] ?? '';
  $password = $_POST['password'] ?? '';

  $staff = findStaff($conn, $username);

  if ($staff && password_verify($password, $staff['password_hash']) && $staff['status'] === 'ACTIVE') {

    // Temporary password: do NOT log in yet. Force a password change first.
    if (!empty($staff['must_change_password'])) {
      session_regenerate_id(true);
      $_SESSION['pw_change_id'] = (int)$staff['id'];
      logAuth($conn, $username, 'LOGIN', 'MUST_CHANGE', (int)$staff['id']);
      header("Location: change_password.php");
      exit;
    }

    $oldSid = session_id();                       // this browser's id before it changes
    session_regenerate_id(true);
    $role = $staff['role'];                       // admin | officer | personnel
    $_SESSION['staff_ids'][$role] = (int)$staff['id'];
    unset($_SESSION['summary_from'], $_SESSION['auth_from']);   // forget old choices

    // Each role keeps its OWN session keys so logins never overwrite each other.
    if ($role === 'admin') {
      $_SESSION['admin_logged_in'] = true;
      $_SESSION['admin_username']  = $username;
      $_SESSION['last_role']       = 'admin';
      closeOldSessions($conn, $username, $oldSid);
      sess_start($conn, 'admin', $username);
      $redirect = 'admin_dashboard.php';

    } elseif ($role === 'officer') {
      $_SESSION['officer_logged_in'] = true;
      $_SESSION['officer_username']  = $username;
      $_SESSION['username']          = $username;   // kept for older pages
      $_SESSION['last_role']         = 'officer';
      closeOldSessions($conn, $username, $oldSid);
      sess_start($conn, 'officer', $username);
      $redirect = 'officer_dashboard.php';

    } else {                                       // personnel
      $_SESSION['security_logged_in'] = true;
      $_SESSION['security_username']  = $username;
      $_SESSION['username']           = $username;
      $_SESSION['last_role']          = 'security';
      closeOldSessions($conn, $username, $oldSid);
      sess_start($conn, 'security', $username);
      $redirect = 'dashboard.php';
    }

    logAuth($conn, $username, 'LOGIN', 'SUCCESS', (int)$staff['id']);
    header("Location: $redirect");
    exit;
  }

  // wrong username, wrong password, or inactive account (same message on purpose)
  logAuth($conn, $username, 'LOGIN', 'FAILED', $staff ? (int)$staff['id'] : null);
  $error = "Invalid username or password";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CACS | Campus Access Control System</title>

  <style>
    *{
      margin:0;
      padding:0;
      box-sizing:border-box;
    }

    html,
    body{
      width:100%;
      height:100%;
      overflow-x:hidden;
      overflow-y:auto;
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      background:#fafbfd;
      color:#16233d;
    }

    body{
      position:relative;
    }

    /* =========================
       BACKGROUND
    ========================= */

    .background{
      position:fixed;
      inset:0;
      z-index:0;
    }

    .background::before{
      content:'';
      position:absolute;
      inset:-30px;

      background:
        linear-gradient(
          rgba(15,36,64,0.58),
          rgba(15,36,64,0.84)
        ),
        url('background (1).jpg') center/cover no-repeat;

      filter:blur(8px);
      transform:scale(1.08);
    }

    /* =========================
       MAIN CONTAINER
    ========================= */

    .container{
      position:relative;
      z-index:2;
      width:100%;
      min-height:100vh;

      display:flex;
      justify-content:center;
      align-items:center;

      padding:30px;
    }

    .dashboard{
      width:100%;
      max-width:1200px;

      display:grid;
      grid-template-columns:minmax(0,1fr) minmax(340px,450px);

      align-items:center;
      gap:clamp(24px,5vw,60px);
    }

    /* =========================
       LEFT SIDE
    ========================= */

    .left{
      padding-left:10px;
    }

    .eyebrow{
      display:inline-flex;
      align-items:center;
      gap:10px;

      padding:8px 16px 8px 8px;

      border-radius:999px;

      background:rgba(255,255,255,0.10);
      border:1px solid rgba(255,255,255,0.22);

      backdrop-filter:blur(6px);

      margin-bottom:22px;
    }

    .eyebrow .mono{
      width:28px;
      height:28px;

      border-radius:50%;
      overflow:hidden;

      background:#ffffff;

      display:flex;
      align-items:center;
      justify-content:center;
    }

    .eyebrow .mono img{
      width:100%;
      height:100%;
      object-fit:cover;
    }

    .eyebrow span{
      font-size:12px;
      font-weight:700;

      letter-spacing:0.16em;
      text-transform:uppercase;

      color:#ffffff;
    }

    .eyebrow .divider-dot{
      width:4px;
      height:4px;

      border-radius:50%;

      background:rgba(255,255,255,0.4);
    }

    .eyebrow .tagline{
      font-size:11px;
      font-weight:500;

      letter-spacing:0.04em;
      text-transform:none;

      color:rgba(255,255,255,0.65);
    }

    .left h1{
      font-size:clamp(34px,5.2vw,64px);
      font-weight:700;

      line-height:0.95;
      letter-spacing:-3px;

      margin-bottom:18px;

      color:#ffffff;
    }

    /* =========================
       LOGIN PANEL
    ========================= */

    .panel{
      padding:44px 46px;

      border-radius:32px;

      background:rgba(255,255,255,0.97);

      border:1px solid rgba(255,255,255,0.8);

      box-shadow:
        0 15px 40px rgba(15,36,64,0.25),
        0 0 35px rgba(88,130,190,0.10);
    }

    .panel-top{
      text-align:center;

      margin-bottom:30px;
    }

    .panel-top img{
      width:70px;
      height:70px;

      object-fit:contain;

      margin-bottom:26px;

      border-radius:14px;
    }

    .panel-top h2{
      font-size:28px;
      font-weight:600;

      margin-bottom:6px;

      color:#16233d;
    }

    .panel-top p{
      font-size:14px;

      color:#8a9bb5;
    }

    /* =========================
       FORM
    ========================= */

    .field{
      margin-bottom:18px;
    }

    .field label{
      display:block;

      margin-bottom:8px;

      font-size:12px;
      font-weight:600;

      letter-spacing:0.08em;
      text-transform:uppercase;

      color:#8a9bb5;
    }

    .input-wrap{
      position:relative;
    }

    .input-wrap .lead{
      position:absolute;
      left:16px;
      top:50%;

      width:18px;
      height:18px;

      transform:translateY(-50%);

      stroke:#9aabc2;
      fill:none;
      stroke-width:1.8;
      stroke-linecap:round;
      stroke-linejoin:round;

      pointer-events:none;
    }

    .input-wrap input{
      width:100%;
      height:50px;

      padding:0 46px 0 46px;

      font-size:15px;
      font-family:inherit;
      color:#16233d;

      background:#f4f7fb;

      border:1px solid #dce4ef;
      border-radius:14px;

      outline:none;

      transition:
        border-color 0.2s ease,
        background 0.2s ease,
        box-shadow 0.2s ease;
    }

    .input-wrap input::placeholder{
      color:#a3b3cc;
    }

    .input-wrap input:focus{
      background:#ffffff;
      border-color:#1f3b63;
      box-shadow:0 0 0 3px rgba(31,59,99,0.12);
    }

    .toggle{
      position:absolute;
      right:8px;
      top:50%;

      width:36px;
      height:36px;

      transform:translateY(-50%);

      display:flex;
      align-items:center;
      justify-content:center;

      background:none;
      border:none;
      border-radius:10px;

      cursor:pointer;
      color:#9aabc2;

      transition:color 0.2s ease, background 0.2s ease;
    }

    .toggle:hover,
    .toggle:focus-visible{
      color:#315b96;
      background:#eef3fa;
      outline:none;
    }

    .toggle svg{
      width:20px;
      height:20px;

      stroke:currentColor;
      fill:none;
      stroke-width:1.8;
      stroke-linecap:round;
      stroke-linejoin:round;
    }

    .toggle .eye-open{ display:none; }
    .toggle.showing .eye-open{ display:block; }
    .toggle.showing .eye-closed{ display:none; }

    .forgot{
      display:block;

      margin:-4px 0 18px auto;
      width:fit-content;

      font-size:13px;
      text-decoration:none;

      color:#16233d;
    }

    .forgot:hover,
    .forgot:focus-visible{
      color:#315b96;
      text-decoration:underline;
    }

    .submit{
      width:100%;
      height:54px;

      font-size:16px;
      font-weight:700;
      font-family:inherit;

      color:#ffffff;
      background:#1f3b63;

      border:none;
      border-radius:14px;

      cursor:pointer;

      transition:
        background 0.2s ease,
        transform 0.2s ease,
        box-shadow 0.2s ease;
    }

    .submit:hover{
      background:#274a7b;
      transform:translateY(-1px);
      box-shadow:0 8px 20px rgba(31,59,99,0.3);
    }

    .submit:focus-visible{
      outline:3px solid rgba(31,59,99,0.35);
      outline-offset:2px;
    }

    .error{
      margin-bottom:18px;
      padding:10px 14px;

      font-size:13px;

      color:#9b2c2c;
      background:#fdecec;

      border:1px solid #f3c4c4;
      border-radius:12px;
    }

    /* =========================
       RESPONSIVE
    ========================= */

    @media(max-width:700px){

      .container{
        min-height:100vh;

        padding:25px;
      }

      .dashboard{
        grid-template-columns:1fr;

        max-width:450px;

        gap:25px;
      }

      .left{
        text-align:center;
        padding-left:0;
      }

      .eyebrow{
        margin-left:auto;
        margin-right:auto;
      }

      .left h1{
        font-size:46px;
        margin-bottom:0;
      }

      .panel{
        padding:32px;
      }
    }

    @media(max-width:500px){

      .container{
        padding:18px;
      }

      .left h1{
        font-size:38px;
        letter-spacing:-2px;
      }

      .eyebrow{
        padding:7px 12px 7px 7px;
      }

      .eyebrow span{
        font-size:9px;
      }

      .eyebrow .tagline,
      .eyebrow .divider-dot{
        display:none;
      }

      .panel{
        padding:26px 22px;
        border-radius:28px;
      }

      .panel-top h2{
        font-size:24px;
      }
    }
  </style>
</head>

<body>

<div class="background"></div>

<div class="container">

  <div class="dashboard">

    <!-- LEFT SIDE -->
    <div class="left">

      <div class="eyebrow">

        <span class="mono">
          <img src="logo.png" alt="CTU logo">
        </span>

        <span>Cebu Technological University</span>

        <span class="divider-dot"></span>

        <span class="tagline">Main Campus</span>

      </div>

      <h1>
        Campus Access<br>
        Control System
      </h1>

    </div>


    <!-- RIGHT SIDE: LOGIN FORM -->
    <div class="panel">

      <div class="panel-top">

        <img src="logo.png" alt="Cebu Technological University Logo">

        <h2>Welcome Back</h2>

        <p>Sign in to your account</p>

      </div>

      <form action="index.php" method="POST" autocomplete="on">

        <?php if ($error): ?>
          <div class="error" role="alert"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <div class="field">
          <label for="username">Username</label>
          <div class="input-wrap">
            <svg class="lead" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="12" cy="8" r="4"></circle>
              <path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"></path>
            </svg>
            <input type="text" id="username" name="username" placeholder="Enter your username" autocomplete="username" value="<?= htmlspecialchars($username) ?>" required autofocus>
          </div>
        </div>

        <div class="field">
          <label for="password">Password</label>
          <div class="input-wrap">
            <svg class="lead" viewBox="0 0 24 24" aria-hidden="true">
              <rect x="4" y="10" width="16" height="10" rx="2"></rect>
              <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
            </svg>
            <input type="password" id="password" name="password" placeholder="Enter your password" autocomplete="current-password" required>
            <button type="button" class="toggle" id="togglePassword" aria-label="Show password">
              <!-- eye with slash (password hidden) -->
              <svg class="eye-closed" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M3 3l18 18"></path>
                <path d="M10.6 6.1A9.6 9.6 0 0 1 12 6c5 0 8.5 4 9.5 6a12.6 12.6 0 0 1-2.6 3.4"></path>
                <path d="M6.6 6.7A12.6 12.6 0 0 0 2.5 12c1 2 4.5 6 9.5 6a9.7 9.7 0 0 0 4-.9"></path>
                <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"></path>
              </svg>
              <!-- open eye (password visible) -->
              <svg class="eye-open" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M2.5 12c1-2 4.5-6 9.5-6s8.5 4 9.5 6c-1 2-4.5 6-9.5 6s-8.5-4-9.5-6z"></path>
                <circle cx="12" cy="12" r="3"></circle>
              </svg>
            </button>
          </div>
        </div>

        <a href="forgot_password.php" class="forgot">Forgot password?</a>

        <button type="submit" class="submit">Sign in</button>

      </form>

    </div>

  </div>

</div>

<script>
  (function(){
    var btn = document.getElementById('togglePassword');
    var input = document.getElementById('password');

    btn.addEventListener('click', function(){
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.classList.toggle('showing', show);
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  })();
</script>

</body>
</html>