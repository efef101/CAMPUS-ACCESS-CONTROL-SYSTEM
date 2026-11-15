<?php
// Active Sessions tracking (table: security_sessions).
// Loaded at the bottom of db.php, so every page and every live-refresh request is covered.
// One browser session can hold several role logins (admin + officer + personnel), so each row
// is keyed by  <php session id>|<role>.  Logging out one role never touches another role's row.

if (!function_exists('sess_roles')) {

  // role key => [session flag, username key, label saved in the table]
  function sess_roles() {
    return [
      'admin'    => ['admin_logged_in',    'admin_username',    'Administrator'],
      'officer'  => ['officer_logged_in',  'officer_username',  'Security Officer'],
      'security' => ['security_logged_in', 'security_username', 'Security Personnel'],
    ];
  }

  function sess_key($role) { return session_id() . '|' . $role; }

  // Call right after a successful login (after session_regenerate_id)
  function sess_start($conn, $role, $username) {
    $roles = sess_roles();
    if (!isset($roles[$role]) || session_status() !== PHP_SESSION_ACTIVE) return;
    try {
      $key = sess_key($role);
      $ip  = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
      $un  = substr((string)$username, 0, 100);
      $lab = $roles[$role][2];

      $d = $conn->prepare("DELETE FROM security_sessions WHERE session_id = ?");
      $d->bind_param('s', $key);
      $d->execute();
      $d->close();

      $i = $conn->prepare("INSERT INTO security_sessions (session_id, username, role, ip_address, login_time, last_activity, status) VALUES (?, ?, ?, ?, NOW(), NOW(), 'active')");
      $i->bind_param('ssss', $key, $un, $lab, $ip);
      $i->execute();
      $i->close();
      $_SESSION['sess_touch'][$role] = time();
    } catch (Throwable $e) {
      error_log('sess_start: ' . $e->getMessage());   // tracking must never block a login
    }
  }

  // Call from the logout pages (before the session flags are removed)
  function sess_end($conn, $role, $status = 'logged_out') {
    if (session_status() !== PHP_SESSION_ACTIVE) return;
    try {
      $key = sess_key($role);
      $u = $conn->prepare("UPDATE security_sessions SET status = ?, logout_time = NOW() WHERE session_id = ? AND status = 'active'");
      $u->bind_param('ss', $status, $key);
      $u->execute();
      $u->close();
    } catch (Throwable $e) {
      error_log('sess_end: ' . $e->getMessage());
    }
  }

  // Runs on every request: keeps "last activity" fresh and applies a force-logout by the administrator.
  function sess_check($conn) {
    if (PHP_SAPI === 'cli' || session_status() !== PHP_SESSION_ACTIVE) return;
    foreach (sess_roles() as $role => $info) {
      list($flag, $ukey) = $info;
      if (empty($_SESSION[$flag])) continue;
      try {
        $key = sess_key($role);
        $st = null;
        $q = $conn->prepare("SELECT status FROM security_sessions WHERE session_id = ?");
        $q->bind_param('s', $key);
        $q->execute();
        $q->bind_result($st);
        $found = $q->fetch();
        $q->close();

        if (!$found) {                       // logged in before tracking existed: create the row now
          sess_start($conn, $role, $_SESSION[$ukey] ?? '');
          continue;
        }
        if ($st === 'forced') {              // the administrator ended this login
          unset($_SESSION[$flag], $_SESSION[$ukey]);
          if ($role !== 'admin' && empty($_SESSION['officer_logged_in']) && empty($_SESSION['security_logged_in'])) unset($_SESSION['username']);
          continue;                          // the page's own login check now sends this role to login.php
        }
        $last = (int)($_SESSION['sess_touch'][$role] ?? 0);
        if ($st !== 'active' || time() - $last >= 30) {
          $u = $conn->prepare("UPDATE security_sessions SET last_activity = NOW(), status = 'active', logout_time = NULL WHERE session_id = ?");
          $u->bind_param('s', $key);
          $u->execute();
          $u->close();
          $_SESSION['sess_touch'][$role] = time();
        }
      } catch (Throwable $e) {
        error_log('sess_check: ' . $e->getMessage());
      }
    }
  }
}

sess_check($conn);