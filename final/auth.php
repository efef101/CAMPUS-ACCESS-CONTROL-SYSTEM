<?php
// auth.php - shared login, role, CSRF and audit helpers (new database).
// Roles: 'admin' | 'officer' | 'personnel'
// Staff IDs are kept per role in $_SESSION['staff_ids'][<role>], set at login.

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
  if (!empty($_SESSION['security_logged_in'])) return 'personnel';
  return null;
}

// staff.id of the account logged in under the current role (0 if none)
function auth_staff_id(): int {
  $role = auth_role();
  return $role ? (int)($_SESSION['staff_ids'][$role] ?? 0) : 0;
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
 * Every role has a row in `staff`, so every role is checked against the database
 * (account must exist, be ACTIVE, and not be waiting for a forced password change).
 */
function auth_state(mysqli $conn): string {
  $role = auth_role();
  if ($role === null) return 'none';

  $id = auth_staff_id();
  if ($id <= 0) return 'inactive';

  $stmt = $conn->prepare("SELECT status, must_change_password FROM staff WHERE id = ? AND role = ?");
  $stmt->bind_param("is", $id, $role);
  $stmt->execute();
  $row = $stmt->get_result()->fetch_assoc();
  $stmt->close();

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
   AUDIT LOG (who logged in / out / did what). Writes to auth_logs.
------------------------------------------------------------------ */

function audit_log(mysqli $conn, string $action, string $status = 'SUCCESS'): void {
  $role = auth_role();
  $usernameKey = ['admin' => 'admin_username', 'officer' => 'officer_username', 'personnel' => 'security_username'][$role] ?? null;
  $actor = $usernameKey ? (string)($_SESSION[$usernameKey] ?? $role) : 'unknown';
  $actor = substr($actor, 0, 100);
  $staffId = auth_staff_id() ?: null;
  $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);

  try {
    $stmt = $conn->prepare("INSERT INTO auth_logs (staff_id, username_snapshot, action, status, ip_address) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("issss", $staffId, $actor, $action, $status, $ip);
    $stmt->execute();
    $stmt->close();
  } catch (Throwable $e) {
    error_log('audit_log failed: ' . $e->getMessage());
  }
}