<?php
// auth.php - shared login, role, CSRF and audit helpers.
// Include at the top of every protected page (after nothing else is output).

if (session_status() === PHP_SESSION_NONE) {
  session_start();
}
require_once __DIR__ . '/db.php';

/* ------------------------------------------------------------------
   ROLE
------------------------------------------------------------------ */

function auth_role(): ?string {
  if (!empty($_SESSION['admin_logged_in']))    return 'admin';
  if (!empty($_SESSION['officer_logged_in']))  return 'officer';
  if (!empty($_SESSION['security_logged_in'])) return 'security';
  return null;
}

function auth_destroy(): void {
  $_SESSION = [];
  if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
  }
  if (session_status() === PHP_SESSION_ACTIVE) {
    session_destroy();
  }
}

/**
 * Returns 'ok' | 'none' | 'inactive' | 'must_change'.
 * Admin has no row in `security`, so only officer/security sessions are
 * checked against the database (account must exist, be ACTIVE, and not be
 * waiting for a forced password change).
 * Requires $_SESSION['security_id'] to be set at login for those roles.
 */
function auth_state(mysqli $conn): string {
  $role = auth_role();
  if ($role === null)    return 'none';
  if ($role === 'admin') return 'ok';

  $id = (int)($_SESSION['security_id'] ?? 0);
  if ($id <= 0) return 'inactive';

  $stmt = $conn->prepare("SELECT status, must_change_password FROM security WHERE id = ?");
  $stmt->bind_param("i", $id);
  $stmt->execute();
  $row = $stmt->get_result()->fetch_assoc();

  if (!$row || $row['status'] !== 'ACTIVE') return 'inactive';
  if ((int)$row['must_change_password'] === 1) return 'must_change';
  return 'ok';
}

/**
 * Page guard. Redirects to login / change_password.php, or 403s when the
 * role is not allowed. Returns the current role.
 * change_password.php itself should pass $allowMustChange = true.
 */
function require_auth(mysqli $conn, array $roles, bool $allowMustChange = false): string {
  $state = auth_state($conn);

  if ($state === 'none') {
    header("Location: login.php");
    exit;
  }
  if ($state === 'inactive') {
    auth_destroy();
    header("Location: login.php");
    exit;
  }
  if ($state === 'must_change' && !$allowMustChange) {
    header("Location: change_password.php");
    exit;
  }

  $role = auth_role();
  if (!in_array($role, $roles, true)) {
    http_response_code(403);
    exit('Access denied.');
  }
  return $role;
}

/* ------------------------------------------------------------------
   CSRF
------------------------------------------------------------------ */

function csrf_token(): string {
  if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
  }
  return $_SESSION['csrf'];
}

function csrf_check(): void {
  if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
    http_response_code(403);
    exit('Invalid request.');
  }
}

/* ------------------------------------------------------------------
   TEMPORARY PASSWORD
------------------------------------------------------------------ */

function generate_temp_password(int $length = 10): string {
  // no look-alike characters (0/O, 1/l/I)
  $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  $max = strlen($chars) - 1;
  $pass = '';
  for ($i = 0; $i < $length; $i++) {
    $pass .= $chars[random_int(0, $max)];
  }
  return $pass;
}

/* ------------------------------------------------------------------
   AUDIT LOG (who did what). Uses authentication_logs.
------------------------------------------------------------------ */

function audit_log(mysqli $conn, string $action, string $status = 'SUCCESS'): void {
  $role  = auth_role();
  $actor = $_SESSION['admin_username'] ?? $_SESSION['username'] ?? ($role ?? 'unknown');

  try {
    $stmt = $conn->prepare("
      INSERT INTO authentication_logs (username, action, status, timestamp)
      VALUES (?, ?, ?, NOW())
    ");
    $stmt->bind_param("sss", $actor, $action, $status);
    $stmt->execute();
  } catch (Throwable $e) {
    error_log('audit_log failed: ' . $e->getMessage());
  }
}