<?php
// User Activity Logs helper (new database): records what administrators, officers and
// personnel DO (reset a password, delete an account, mark an alumni, register a visitor...).
// Use:  log_activity($conn, 'RESET PASSWORD', 'juan01');
// For alumni actions, pass details as 'ID <id_number>' so the person can be linked.
// A logging problem must never stop the action itself, so errors only go to the PHP error log.

if (!function_exists('log_activity')) {

  // Who is acting? $role can be forced ('admin' | 'officer' | 'security');
  // otherwise it is worked out from the session (the most recent login wins when several are open).
  function activity_actor($role = null) {
    $map = [
      'admin'    => ['admin_logged_in',    'admin_username',    'Administrator',      'admin'],
      'officer'  => ['officer_logged_in',  'officer_username',  'Security Officer',   'officer'],
      'security' => ['security_logged_in', 'security_username', 'Security Personnel', 'personnel'],
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
    if ($role === null) return ['unknown', 'Unknown', null, null];
    $staffId = (int)($_SESSION['staff_ids'][$map[$role][3]] ?? 0) ?: null;
    return [(string)($_SESSION[$map[$role][1]] ?? $_SESSION['username'] ?? $role), $map[$role][2], $staffId, $map[$role][3]];
  }

  function log_activity($conn, $action, $target = '', $details = '', $role = null) {
    try {
      list($actor, $label, $staffId) = activity_actor($role);
      $actor   = mb_substr($actor, 0, 100);
      $action  = mb_substr((string)$action, 0, 40);
      $target  = mb_substr((string)$target, 0, 150);
      $details = mb_substr((string)$details, 0, 255);
      $ip      = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);

      // Link alumni actions to the person (details look like "ID 1234567")
      $personId = null;
      if (in_array($action, ['MARK ALUMNI', 'UNDO ALUMNI'], true) && strpos($details, 'ID ') === 0) {
        $idNumber = substr($details, 3);
        $p = $conn->prepare("SELECT id FROM people WHERE id_number = ? LIMIT 1");
        $p->bind_param('s', $idNumber);
        $p->execute();
        $row = $p->get_result()->fetch_assoc();
        $p->close();
        $personId = $row ? (int)$row['id'] : null;
      }

      $q = $conn->prepare("INSERT INTO activity_logs (actor_staff_id, actor_name_snapshot, actor_role, action, target_person_id, target_label, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
      $q->bind_param('isssisss', $staffId, $actor, $label, $action, $personId, $target, $details, $ip);
      $q->execute();
      $q->close();
    } catch (Throwable $e) {
      error_log('log_activity failed: ' . $e->getMessage());
    }
  }
}

/* Can this alumni be undone? Only when the last logged change for that person was a "MARK ALUMNI". */
if (!function_exists('can_undo_alumni')) {
  function can_undo_alumni($conn, $id_number) {
    try {
      $q = $conn->prepare("SELECT a.action FROM activity_logs a JOIN people p ON p.id = a.target_person_id WHERE p.id_number = ? AND a.action IN ('MARK ALUMNI','UNDO ALUMNI') ORDER BY a.id DESC LIMIT 1");
      $q->bind_param('s', $id_number);
      $q->execute();
      $r = $q->get_result()->fetch_assoc();
      $q->close();
      return $r && $r['action'] === 'MARK ALUMNI';
    } catch (Throwable $e) { return false; }
  }
}