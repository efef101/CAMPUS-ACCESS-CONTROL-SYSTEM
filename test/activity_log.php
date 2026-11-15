<?php
// User Activity Logs helper: records what administrators, officers and personnel DO
// (reset a password, delete an account, mark an alumni, register a visitor...).
// Use:  log_activity($conn, 'RESET PASSWORD', 'juan01');
// A logging problem must never stop the action itself, so errors only go to the PHP error log.

if (!function_exists('log_activity')) {

  // Who is acting? $role can be forced ('admin' | 'officer' | 'security');
  // otherwise it is worked out from the session (the most recent login wins when several are open).
  function activity_actor($role = null) {
    $map = [
      'admin'    => ['admin_logged_in',    'admin_username',    'Administrator'],
      'officer'  => ['officer_logged_in',  'officer_username',  'Security Officer'],
      'security' => ['security_logged_in', 'security_username', 'Security Personnel'],
    ];
    if ($role === null || !isset($map[$role]) || empty($_SESSION[$map[$role][0]])) {
      $role = null;
      $last = $_SESSION['last_role'] ?? '';
      if (isset($map[$last]) && !empty($_SESSION[$map[$last][0]])) {
        $role = $last;
      } else {
        foreach ($map as $k => $m) { if (!empty($_SESSION[$m[0]])) { $role = $k; break; } }
      }
    }
    if ($role === null) return ['unknown', 'Unknown'];
    return [(string)($_SESSION[$map[$role][1]] ?? $_SESSION['username'] ?? $role), $map[$role][2]];
  }

  function log_activity($conn, $action, $target = '', $details = '', $role = null) {
    try {
      list($actor, $label) = activity_actor($role);
      $actor   = mb_substr($actor, 0, 100);
      $action  = mb_substr((string)$action, 0, 40);
      $target  = mb_substr((string)$target, 0, 150);
      $details = mb_substr((string)$details, 0, 255);
      $ip      = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
      $q = $conn->prepare("INSERT INTO activity_logs (actor, actor_role, action, target, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)");
      $q->bind_param('ssssss', $actor, $label, $action, $target, $details, $ip);
      $q->execute();
      $q->close();
    } catch (Throwable $e) {
      error_log('log_activity failed: ' . $e->getMessage());
    }
  }
}

/* Can this alumni be undone? Only when the last logged change for that ID was a "MARK ALUMNI". */
if (!function_exists('can_undo_alumni')) {
  function can_undo_alumni($conn, $id_number) {
    try {
      $d = 'ID ' . $id_number;
      $q = $conn->prepare("SELECT action FROM activity_logs WHERE action IN ('MARK ALUMNI','UNDO ALUMNI') AND details = ? ORDER BY id DESC LIMIT 1");
      $q->bind_param('s', $d);
      $q->execute();
      $r = $q->get_result()->fetch_assoc();
      $q->close();
      return $r && $r['action'] === 'MARK ALUMNI';
    } catch (Throwable $e) { return false; }
  }
}