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
   One browser can be logged in as several roles at once (for example admin
   in one tab and officer in another tab of the same browser). So the page
   decides which role it runs as: require_auth() picks the first role that
   the page allows AND that is logged in, and remembers it for this request.
------------------------------------------------------------------ */

// role => [login flag, username key]
function auth_role_keys(): array {
  return [
    'admin'     => ['admin_logged_in',    'admin_username'],
    'officer'   => ['officer_logged_in',  'officer_username'],
    'personnel' => ['security_logged_in', 'security_username'],
  ];
}

// Every role this browser is currently logged in as.
function auth_logged_roles(): array {
  $out = [];
  foreach (auth_role_keys() as $role => $k) {
    if (!empty($_SESSION[$k[0]])) $out[] = $role;
  }
  return $out;
}

// The role this request runs as (set by require_auth), else the first logged-in role.
function auth_role(): ?string {
  if (!empty($GLOBALS['AUTH_ROLE']) && in_array($GLOBALS['AUTH_ROLE'], auth_logged_roles(), true)) {
    return $GLOBALS['AUTH_ROLE'];
  }
  $all = auth_logged_roles();
  return $all[0] ?? null;
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

// Log out ONE role only; the browser's other role logins stay.
function auth_drop_role(string $role): void {
  $keys = auth_role_keys();
  if (!isset($keys[$role])) return;
  unset($_SESSION[$keys[$role][0]], $_SESSION[$keys[$role][1]], $_SESSION['staff_ids'][$role]);
  if (!auth_logged_roles()) auth_destroy();
}

/**
 * Returns 'ok' | 'none' | 'inactive' | 'must_change' for the given role
 * (default: the current role). Every role has a row in `staff`, so it is checked
 * against the database: must exist, be ACTIVE, and not need a password change.
 */
function auth_state(mysqli $conn, ?string $role = null): string {
  $role = $role ?? auth_role();
  if ($role === null || !in_array($role, auth_logged_roles(), true)) return 'none';

  $id = (int)($_SESSION['staff_ids'][$role] ?? 0);
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
 * Page guard. Redirects to login / change_password.php, or 403s when none of
 * this browser's logins is allowed on the page. Returns the role the page runs as.
 * change_password.php itself should pass $allowMustChange = true.
 */
function require_auth(mysqli $conn, array $roles, bool $allowMustChange = false): string {
  $logged = auth_logged_roles();
  if (!$logged) {
    header("Location: login.php");
    exit;
  }

  // Use the first role this page allows that this browser is logged in as.
  $role = null;
  foreach ($roles as $r) {
    if (in_array($r, $logged, true)) { $role = $r; break; }
  }
  if ($role === null) {
    http_response_code(403);
    exit('Access denied.');
  }

  $state = auth_state($conn, $role);
  if ($state === 'inactive') {
    auth_drop_role($role);
    header("Location: login.php");
    exit;
  }
  if ($state === 'must_change' && !$allowMustChange) {
    header("Location: change_password.php");
    exit;
  }

  $GLOBALS['AUTH_ROLE'] = $role;   // auth_role(), auth_staff_id() and audit_log() now use this role
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