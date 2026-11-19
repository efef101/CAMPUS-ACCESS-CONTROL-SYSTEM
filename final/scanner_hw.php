<?php
session_start();
include 'db.php';
include_once 'auth.php';
require_once __DIR__ . '/scan_security.php';

// A scan request with an ended session gets a JSON answer; the page itself gets a login redirect
if ($_SERVER['REQUEST_METHOD'] === 'POST' && auth_role() !== 'personnel') {
  header('Content-Type: application/json; charset=utf-8');
  http_response_code(401);
  echo json_encode(['result' => 'DENIED', 'message' => 'Session expired. Please log in again.']);
  exit;
}

require_auth($conn, ['personnel']);

define('FACE_MATCH_THRESHOLD', 0.45);   // lower = stricter (0.6 is face-api's default)
define('VISITOR_PASS_HOURS', 12);       // a visitor pass is valid this many hours from the first entry

// The direction of the current scan (IN or OUT). Decides which gate screen gets it.
// Stays null until a valid scan request sets it, so nothing is shown for other requests.
$scanDir = null;

// ============================================================
// HELPERS
// ============================================================

// Saves the latest scan for the gate screens. IN scans go to gate_latest_in.json,
// OUT scans go to gate_latest_out.json. Only public-safe fields are saved.
function gate_publish(array $a) {
  global $scanDir;
  if ($scanDir === null) return;   // no valid direction: nothing to show on a gate screen

  $d = [
    'result'  => $a['result'],
    'name'    => $a['name'] ?? null,
    'role'    => $a['role'] ?? null,
    'info'    => $a['info'] ?? [],
    'group'   => $a['group'] ?? null,
    'photo'   => $a['photo'] ?? null,
    'alumni'  => !empty($a['alumni']),
    'message' => $a['message'] ?? '',
    'seq'     => (string)round(microtime(true) * 1000),
    'time'    => time(),
  ];
  $file = __DIR__ . '/gate_latest_' . strtolower($scanDir) . '.json';
  @file_put_contents($file, json_encode($d, JSON_UNESCAPED_UNICODE), LOCK_EX);
}

function out(array $a) {
  // Only real gate scans (not patrol checks, logs or face compares) go to the gate screens
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? 'scan') === 'scan' && isset($a['result'])) {
    gate_publish($a);
  }
  echo json_encode($a, JSON_UNESCAPED_UNICODE);
  exit;
}

function faceSrc($v) {
  $v = trim((string)$v);
  if ($v === '') return null;
  return str_starts_with($v, 'data:image') ? $v : 'data:image/jpeg;base64,' . $v;
}

function infoList(array $vals) {
  return array_values(array_filter($vals, fn($x) => trim((string)$x) !== ''));
}

function euclid($a, $b) {
  $s = 0.0;
  for ($i = 0; $i < 128; $i++) { $d = (float)$a[$i] - (float)$b[$i]; $s += $d * $d; }
  return sqrt($s);
}

// Was this person (column 'person_id') or visitor (column 'visitor_id') already scanned in the last 5 seconds?
function recentlyLogged($conn, $column, $id) {
  $q = $conn->prepare("SELECT id FROM access_logs WHERE $column = ? AND event <> 'DENIED' AND logged_at >= NOW() - INTERVAL 5 SECOND LIMIT 1");
  $q->bind_param("i", $id);
  $q->execute();
  return $q->get_result()->num_rows > 0;
}

// Names of the members of a group visitor (the leader is stored in visitors.name)
function groupMembers($conn, $visitorId) {
  $q = $conn->prepare("SELECT member_name FROM visitor_group_members WHERE visitor_id = ? ORDER BY id");
  $q->bind_param("i", $visitorId);
  $q->execute();
  $rows = $q->get_result()->fetch_all(MYSQLI_ASSOC);
  return array_column($rows, 'member_name');
}

// Saves one ENTRY or EXIT row, with the guard's staff row and username
function writeLog($conn, $event, $personType, $personId, $visitorId, $idNumber, $name) {
  $staffId = $_SESSION['staff_ids']['personnel'] ?? null;
  $guard   = mb_substr((string)($_SESSION['security_username'] ?? ''), 0, 50);
  $log = $conn->prepare("INSERT INTO access_logs (event, person_type, person_id, visitor_id, id_number, name_snapshot, staff_id, guard_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  $log->bind_param("ssiissis", $event, $personType, $personId, $visitorId, $idNumber, $name, $staffId, $guard);
  $log->execute();
}

// ============================================================
// AJAX HANDLER (scan + patrol check + optional face compare)
// ============================================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  header('Content-Type: application/json; charset=utf-8');
  $action = $_POST['action'] ?? 'scan';
  $code   = trim($_POST['code'] ?? $_POST['barcode'] ?? '');

  // ---------- RECENT LOGS (for the panel next to the scanner) ----------
  if ($action === 'logs') {
    session_write_close();
    $statusMap = ['ENTRY' => 'IN', 'EXIT' => 'OUT', 'DENIED' => 'DENIED'];
    $logs = [];
    $r = $conn->query("SELECT name_snapshot, event, reason, flagged, logged_at FROM access_logs ORDER BY logged_at DESC, id DESC LIMIT 10");
    while ($r && $row = $r->fetch_assoc()) {
      $logs[] = [
        'name'    => $row['name_snapshot'],
        'status'  => $statusMap[$row['event']] ?? 'DENIED',
        'reason'  => $row['reason'],
        'flagged' => (int)$row['flagged'] === 1,
        'time'    => date('M j, g:i A', strtotime($row['logged_at'])),
      ];
    }
    out(['logs' => $logs]);
  }

  // ---------- PATROL CHECK (read-only: never changes status or writes IN/OUT logs) ----------
  // Used by mobile_scanning.php when a roving guard checks someone's ID on campus.
  if ($action === 'check') {
    if ($code === '') {
      out(['result' => 'DENIED', 'message' => 'No code received. Scan the ID again.']);
    }

    // Visitor?
    $stmt = $conn->prepare("SELECT * FROM visitors WHERE qr_code = ? ORDER BY (status = 'IN') DESC, id DESC LIMIT 1");
    $stmt->bind_param("s", $code);
    $stmt->execute();
    $v = $stmt->get_result()->fetch_assoc();

    if ($v) {
      $inside  = ($v['status'] === 'IN');
      $expired = !empty($v['expires_at']) && strtotime($v['expires_at']) < time();

      // Group details for the patrol screen (null for an individual)
      $isGroupV = ($v['visitor_type'] ?? '') === 'GROUP';
      $vGroup = $isGroupV ? [
        'name'        => !empty($v['group_name']) ? $v['group_name'] : $v['name'],
        'leader'      => $v['name'],
        'size'        => (int)$v['group_size'],
        'members'     => groupMembers($conn, (int)$v['id']),
        'purpose'     => $v['purpose'] ?? '',
        'destination' => $v['destination'] ?? '',
      ] : null;
      out([
        'result'   => $inside ? 'INSIDE' : 'NOT_INSIDE',
        'name'     => (($v['visitor_type'] ?? '') === 'GROUP' && !empty($v['group_name'])) ? $v['group_name'] : $v['name'],
        'role'     => 'Visitor',
        'id'       => null,
        'photo'    => null,
        'has_face' => false,
        'group'    => $vGroup,
        'info'     => infoList([$v['purpose'] ?? '', $v['destination'] ?? '']),
        'message'  => $inside
          ? ($expired ? 'Visitor is inside but the QR has EXPIRED' : 'Visitor is registered as inside')
          : (!empty($v['used_at']) ? 'Visitor has left. QR already used.' : 'Visitor is NOT checked in. Possible unauthorized entry.'),
      ]);
    }

    // Person? (face image and descriptor now live in face_data)
    $stmt = $conn->prepare("SELECT p.*, fd.descriptor AS face_descriptor, fd.image AS face_image
                            FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id
                            WHERE p.id_number = ?");
    $stmt->bind_param("s", $code);
    $stmt->execute();
    $u = $stmt->get_result()->fetch_assoc();

    if (!$u) {
      $event = record_denial($conn, $code, $code, 'Unknown', 'UNKNOWN_ID');
      out(['result' => 'DENIED', 'message' => 'ID not found in the system', 'id' => $code, 'suspicious' => $event['suspicious']]);
    }

    $inside = ($u['status'] === 'IN');
    out([
      'result'   => $inside ? 'INSIDE' : 'NOT_INSIDE',
      'name'     => trim($u['first_name'] . ' ' . $u['last_name']),
      'role'     => $u['role'],
      'id'       => $u['id_number'],
      'photo'    => faceSrc($u['face_image'] ?? ''),
      'has_face' => !empty($u['face_descriptor']),
      'alumni'   => strtolower(trim((string)$u['role'])) === 'alumni',
      'info'     => infoList([$u['course'] ?? '', $u['department'] ?? '', $u['position'] ?? '']),
      'message'  => $inside
        ? 'Registered as INSIDE the campus'
        : 'System shows this person is OUTSIDE. Possible tailgating or borrowed ID.',
    ]);
  }

  // ---------- OPTIONAL FACE COMPARE (guard pressed "Verify face") ----------
  if ($action === 'compare') {
    // Patrol mode: the guard is only checking someone, so never cancel an entry/exit
    $isPatrol = ($_POST['patrol'] ?? '') === '1';

    // Lock out after 5 failed attempts within 5 minutes
    $_SESSION['face_fails'] = array_filter($_SESSION['face_fails'] ?? [], fn($t) => $t > time() - 300);
    if (count($_SESSION['face_fails']) >= 5) {
      out(['error' => 'Too many failed attempts. Please wait a few minutes.']);
    }

    $descriptor = json_decode($_POST['face_descriptor'] ?? '', true);
    if ($code === '' || !is_array($descriptor) || count($descriptor) !== 128) {
      out(['error' => 'Invalid request']);
    }

    $stmt = $conn->prepare("SELECT p.id, p.first_name, p.last_name, p.role, fd.descriptor AS face_descriptor
                            FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id
                            WHERE p.id_number = ?");
    $stmt->bind_param("s", $code);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!$row) out(['error' => 'User not found']);
    $who = trim($row['first_name'] . ' ' . $row['last_name']);
    $stored = json_decode($row['face_descriptor'] ?? '', true);
    if (!is_array($stored) || count($stored) !== 128) {
      out(['error' => 'No face enrolled for this user']);
    }

    foreach ($descriptor as $value) {
      if (!is_numeric($value) || !is_finite((float)$value)) {
        out(['error' => 'Invalid face descriptor']);
      }
    }
    $descriptor = array_values($descriptor);
    $stored     = array_values($stored);
    $distance   = euclid($descriptor, $stored);
    error_log("scanner verify: id=$code distance=" . round($distance, 3) . ($isPatrol ? ' (patrol)' : ''));

    // Reject if a DIFFERENT registered person matches this face better than the scanned ID does
    $matchesSomeoneElse = false;
    $others = $conn->query("SELECT p.id_number, fd.descriptor
                            FROM face_data fd JOIN people p ON p.id = fd.person_id
                            WHERE fd.descriptor IS NOT NULL AND fd.descriptor <> ''");
    if ($others) {
      while ($o = $others->fetch_assoc()) {
        if ((string)$o['id_number'] === (string)$code) continue;
        $od = json_decode($o['descriptor'], true);
        if (!is_array($od) || count($od) !== 128) continue;
        if (euclid($descriptor, array_values($od)) < $distance) { $matchesSomeoneElse = true; break; }
      }
      $others->free();
    }

    $ls = $_SESSION['last_scan'] ?? null;
    $sameScan = !$isPatrol && $ls && $ls['code'] === $code && (time() - $ls['time']) < 300;

    if ($distance <= FACE_MATCH_THRESHOLD && !$matchesSomeoneElse) {
      if ($sameScan && !empty($ls['reverted'])) {
        out(['match' => true, 'name' => $who, 'note' => 'Face matches, but this scan was already cancelled. Scan the badge again.']);
      }
      out(['match' => true, 'name' => $who]);
    }

    // FAILED: cancel the entry/exit that this scan just recorded (gate scanner only)
    $_SESSION['face_fails'][] = time();
    $reverted = false;
    $message  = $isPatrol ? 'Face does not match this ID. Possible borrowed ID.' : 'Face does not match.';

    if ($sameScan && empty($ls['reverted'])) {
      $rev = $conn->prepare("UPDATE people SET status = ? WHERE id_number = ? AND status = ?");
      $rev->bind_param("sss", $ls['restore'], $code, $ls['to']);
      $rev->execute();
      if ($rev->affected_rows > 0) {
        $_SESSION['last_scan']['reverted'] = true;
        $reverted = true;
        $message  = ($ls['type'] === 'ENTRY')
          ? 'Face does not match. Entry not granted.'
          : 'Face does not match. Exit not recorded.';
      }
    }
    // Always record the mismatch as a denial (counts toward suspicious flagging)
    $event = record_denial($conn, $code, $who, (string)$row['role'], 'FACE_MISMATCH', (int)$row['id']);
    out(['match' => false, 'name' => $who, 'reverted' => $reverted, 'message' => $message, 'suspicious' => $event['suspicious']]);
  }

  // ---------- SCAN ----------
  // The direction the guard chose on the switch: IN (entry) or OUT (exit)
  $dir = strtoupper(trim((string)($_POST['mode'] ?? '')));
  if ($dir !== 'IN' && $dir !== 'OUT') {
    out(['result' => 'DENIED', 'message' => 'Choose IN or OUT before scanning.']);
  }
  $scanDir = $dir;   // from here on, this scan goes to the matching gate screen

  if ($code === '') {
    out(['result' => 'DENIED', 'message' => 'No code received. Scan the badge again.']);
  }

  // Visitors first (an individual or a group; a group shares one QR code)
  $stmt = $conn->prepare("SELECT * FROM visitors WHERE qr_code = ? ORDER BY (status = 'IN') DESC, id DESC LIMIT 1");
  $stmt->bind_param("s", $code);
  $stmt->execute();
  $visitor = $stmt->get_result()->fetch_assoc();

  if ($visitor) {
    $visitorId = (int)$visitor['id'];
    $isGroup   = ($visitor['visitor_type'] ?? '') === 'GROUP';
    $members   = $isGroup ? groupMembers($conn, $visitorId) : [];
    // A group is logged under its group name; an individual under their own name
    $logName   = ($isGroup && !empty($visitor['group_name'])) ? $visitor['group_name'] : $visitor['name'];

    // Group details for the group card (null for an individual, so the card is not shown)
    $group = $isGroup ? [
      'name'        => $logName,
      'leader'      => $visitor['name'],
      'size'        => (int)$visitor['group_size'],
      'members'     => $members,
      'purpose'     => $visitor['purpose'] ?? '',
      'destination' => $visitor['destination'] ?? '',
    ] : null;

    $person = [
      'name'     => $logName,
      'role'     => $isGroup ? 'Group Visitor' : 'Visitor',
      'id'       => null,
      'photo'    => null,
      'has_face' => false,
      'group'    => $group,
      'info'     => infoList([$visitor['purpose'] ?? '', $visitor['destination'] ?? '']),
    ];
    $logId     = 'V' . $visitorId;      // label used for denials and flags
    $isEntry   = ($visitor['status'] !== 'IN');

    // Direction check: IN only lets someone in, OUT only lets someone out
    if ($dir === 'IN' && !$isEntry) {
      out($person + ['result' => 'DENIED', 'message' => 'Already inside. Switch to OUT to record the exit.']);
    }
    if ($dir === 'OUT' && $isEntry) {
      out($person + ['result' => 'DENIED', 'message' => 'Not inside. Switch to IN to record the entry.']);
    }

    // Expiry only blocks ENTRY; visitors already inside can always leave
    if ($isEntry && !empty($visitor['expires_at']) && strtotime($visitor['expires_at']) < time()) {
      $event = record_denial($conn, $logId, $logName, 'Visitor', 'QR_EXPIRED', null, $visitorId);
      out($person + ['result' => 'DENIED', 'message' => 'QR expired', 'suspicious' => $event['suspicious']]);
    }
    // QR already used (the visitor went out): deny any further scan
    if (!empty($visitor['used_at'])) {
      $event = record_denial($conn, $logId, $logName, 'Visitor', 'QR_USED', null, $visitorId);
      out($person + ['result' => 'DENIED', 'message' => 'QR already used. Visitor must register again.', 'suspicious' => $event['suspicious']]);
    }

    if (recentlyLogged($conn, 'visitor_id', $visitorId)) {
      out($person + ['result' => 'DUPLICATE', 'message' => 'Already scanned a moment ago']);
    }

    $to   = $isEntry ? 'IN' : 'OUT';
    $type = $isEntry ? 'ENTRY' : 'EXIT';

    // Atomic toggle: only succeeds if the status hasn't changed since we read it
    // The pass starts on the first entry: expires_at is set once, when the visitor enters for the first time.
    // When the visitor goes OUT, the QR is marked used (used_at), so it cannot be scanned again.
    $hours = (int)VISITOR_PASS_HOURS;
    $upd = $conn->prepare("UPDATE visitors
                           SET status = ?,
                               used_at = IF(? = 'OUT', NOW(), used_at),
                               expires_at = IF(? = 'IN' AND expires_at IS NULL, NOW() + INTERVAL $hours HOUR, expires_at)
                           WHERE id = ? AND status <=> ?");
    $upd->bind_param("sssis", $to, $to, $to, $visitorId, $visitor['status']);
    $upd->execute();
    if ($upd->affected_rows === 0) {
      out($person + ['result' => 'DENIED', 'message' => 'Duplicate scan, please scan again']);
    }

    writeLog($conn, $type, 'visitor', null, $visitorId, $logId, $logName);
    out($person + ['result' => $type, 'message' => $isEntry ? 'Entry granted' : 'Exit recorded']);
  }

  // Then people (face image and descriptor come from face_data)
  $stmt = $conn->prepare("SELECT p.*, fd.descriptor AS face_descriptor, fd.image AS face_image
                          FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id
                          WHERE p.id_number = ?");
  $stmt->bind_param("s", $code);
  $stmt->execute();
  $user = $stmt->get_result()->fetch_assoc();

  if (!$user) {
    $event = record_denial($conn, $code, $code, 'Unknown', 'UNKNOWN_ID');
    out(['result' => 'DENIED', 'message' => 'ID not found', 'id' => $code, 'suspicious' => $event['suspicious']]);
  }

  $personId = (int)$user['id'];
  $name     = trim($user['first_name'] . ' ' . $user['last_name']);
  $person   = [
    'name'     => $name,
    'role'     => $user['role'],
    'id'       => $user['id_number'],
    'photo'    => faceSrc($user['face_image'] ?? ''),
    'has_face' => !empty($user['face_descriptor']),
    'alumni'   => strtolower(trim((string)$user['role'])) === 'alumni',
    'info'     => infoList([$user['course'] ?? '', $user['department'] ?? '', $user['position'] ?? '']),
  ];
  $isEntry = ($user['status'] !== 'IN');

  // Not registered yet: the admin added the account, but no face was captured at registration
  if (trim((string)($user['face_descriptor'] ?? '')) === '') {
    $event = record_denial($conn, $code, $name, (string)$user['role'], 'NOT_REGISTERED', $personId);
    out($person + ['result' => 'DENIED', 'message' => 'Not registered yet. Complete registration first.', 'suspicious' => $event['suspicious']]);
  }

  // Direction check: IN only lets someone in, OUT only lets someone out
  if ($dir === 'IN' && !$isEntry) {
    out($person + ['result' => 'DENIED', 'message' => 'Already inside. Switch to OUT to record the exit.']);
  }
  if ($dir === 'OUT' && $isEntry) {
    out($person + ['result' => 'DENIED', 'message' => 'Not inside. Switch to IN to record the entry.']);
  }

  if (recentlyLogged($conn, 'person_id', $personId)) {
    out($person + ['result' => 'DUPLICATE', 'message' => 'Already scanned a moment ago']);
  }

  $to   = $isEntry ? 'IN' : 'OUT';
  $type = $isEntry ? 'ENTRY' : 'EXIT';

  $upd = $conn->prepare("UPDATE people SET status = ? WHERE id = ? AND status <=> ?");
  $upd->bind_param("sis", $to, $personId, $user['status']);
  $upd->execute();
  if ($upd->affected_rows === 0) {
    out($person + ['result' => 'DENIED', 'message' => 'Duplicate scan, please scan again']);
  }

  writeLog($conn, $type, strtolower((string)$user['role']), $personId, null, $user['id_number'], $name);
  $_SESSION['last_scan'] = [
    'code' => $code, 'name' => $name, 'role' => $user['role'],
    'restore' => $user['status'] ?: 'OUT',   // status before this scan
    'to' => $to, 'type' => $type, 'time' => time(), 'reverted' => false,
  ];
  out($person + ['result' => $type, 'message' => $isEntry ? 'Entry granted' : 'Exit recorded']);
}
header("Cache-Control: no-cache, no-store, must-revalidate");
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scanner</title>
  <style>
  * { box-sizing: border-box; }

  body {
    margin: 0; min-height: 100vh; padding: 24px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #fafbfd;
    display: grid; grid-template-columns: 1fr 1fr; gap: 24px; align-items: stretch; align-content: center;
  }

  .container {
    width: 100%; max-width: 480px; margin: 0 auto; align-self: center; padding: 30px; background: #fff;
    border-radius: 18px; border: 1px solid #dce4ef;
    box-shadow: 0 1px 3px rgba(22,58,94,0.05);
    text-align: center; color: #16233d;
  }

  h2 { font-size: 18px; font-weight: 600; margin: 0 0 6px; }
  .subtitle { font-size: 12px; color: #8a9bb5; margin-bottom: 20px; }

  #readerVisual {
    width: 100%; min-height: 320px;
    border: none; background: transparent;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 8px; padding: 16px;
    transition: all 0.15s ease;
  }
  .duplicate #badge { background: #d99a0b; }

  #idleIcon { font-size: 40px; opacity: 0.6; }

  #photo {
    display: none;
    width: 150px; height: 150px; border-radius: 50%;
    object-fit: cover; border: 3px solid #fff;
    box-shadow: 0 2px 10px rgba(22,35,61,0.15);
    background: #dce4ef;
  }
  #personName { font-size: 20px; font-weight: 700; display: none; }
  #personMeta { font-size: 13px; color: #6b7a94; display: none; white-space: pre-line; line-height: 1.5; }
  #badge {
    display: none; padding: 6px 16px; border-radius: 999px;
    font-size: 14px; font-weight: 700; color: #fff; letter-spacing: 0.04em;
  }
  .entry  #badge { background: #16a34a; }
  .exit   #badge { background: #2563eb; }
  .denied #badge { background: #dc2626; }

  #alumniBadge {
    display: none; padding: 5px 16px; border-radius: 999px;
    font-size: 13px; font-weight: 800; letter-spacing: 0.08em;
    color: #5b3b00; background: linear-gradient(135deg, #f7d774, #d4a017);
    border: 1px solid #b7791f;
  }

  #suspiciousBanner {
    display: none; width: 100%; padding: 12px; border-radius: 10px;
    color: #fff; background: #b91c1c; font-weight: 800; letter-spacing: .03em;
    animation: pulse 0.8s ease-in-out infinite alternate;
  }
  @keyframes pulse { from { opacity: 1; } to { opacity: .65; } }

  #statusText { font-size: 13px; color: #6b7a94; font-weight: 600; }

  #verifyBtn {
    display: none; margin-top: 6px; padding: 8px 18px;
    background: #fff; color: #16233d; border: 1px solid #c7d7ec; border-radius: 10px;
    font: 600 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; cursor: pointer;
  }
  #verifyBtn:hover { background: #f4f7fb; }

  .logs-panel {
    width: 100%; padding: 28px; background: #fff;
    border-radius: 18px; border: 1px solid #dce4ef;
    box-shadow: 0 1px 3px rgba(22,58,94,0.05); color: #16233d;
  }
  .logs-panel h3 { margin: 0 0 18px; font-size: 20px; font-weight: 600; }
  .logs-panel table { width: 100%; border-collapse: collapse; }
  .logs-panel th {
    text-align: left; font-size: 12px; color: #96a6c0;
    text-transform: uppercase; letter-spacing: 0.06em; padding-bottom: 12px;
  }
  .logs-panel td { padding: 14px 0; border-top: 1px solid #eef2f8; font-size: 16px; color: #3c4a63; }
  .lbadge { display: inline-block; padding: 3px 12px; border-radius: 20px; font-size: 13px; font-weight: 600; }
  .lbadge.in     { background: #e8f8ef; color: #16a34a; }
  .lbadge.out    { background: #e8f0fd; color: #2563eb; }
  .lbadge.denied { background: #fdeaea; color: #dc2626; }
  .lflag { margin-left: 6px; font-size: 12px; font-weight: 700; color: #b91c1c; }
  .lreason { display: block; font-size: 11px; color: #96a6c0; font-weight: 500; }
  .logs-empty { color: #b7c3d6; padding: 12px 0; }

  .inside     #badge { background: #16a34a; }
  .not_inside #badge { background: #dc2626; }

  /* IN / OUT switch the personnel uses to choose the scan direction */
  .dir-switch { display: inline-flex; margin-bottom: 14px; border: 1px solid #c7d7ec; border-radius: 999px; overflow: hidden; }
  .dir-btn { border: none; background: #fff; color: #6b7a94; padding: 10px 28px; font: 700 15px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; cursor: pointer; }
  .dir-btn.active.in  { background: #16a34a; color: #fff; }
  .dir-btn.active.out { background: #2563eb; color: #fff; }

  /* Camera backup (laptop webcam), opened from the dashboard sidebar */
  .cam-btn {
    display: block; width: 100%; margin-bottom: 16px; padding: 12px 16px; background: #fff; color: #16233d;
    border: 1px solid #c7d7ec; border-radius: 12px; font: 600 14px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; cursor: pointer;
  }
  .cam-btn:hover { background: #f4f7fb; }
  #camPanel { display: none; margin-bottom: 16px; }
  #camVideo { width: 100%; max-height: 260px; border-radius: 12px; background: #0f2440; object-fit: cover; }
  #camSwitch { display: none; margin-top: 8px; padding: 8px 14px; background: #fff; color: #16233d; border: 1px solid #c7d7ec; border-radius: 10px; font: 600 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; cursor: pointer; }
  #camSwitch:disabled { opacity: .6; cursor: default; }
  #camHint { font-size: 12px; color: #6b7a94; margin-top: 8px; }

  /* Group visitor card (shown only when a group QR code is scanned) */
  #groupCard { display: none; width: 100%; text-align: left; background: #fff; border: 1px solid #dce4ef; border-radius: 18px; padding: 22px; }
  #groupCard .gc-top { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
  #groupCard .gc-label { font-size: 12px; font-weight: 700; color: #6b7a94; letter-spacing: .04em; }
  #groupCard .gc-badge { display: inline-block; padding: 6px 16px; border-radius: 999px; color: #fff; font-size: 14px; font-weight: 700; letter-spacing: .04em; }
  #groupCard .gc-name { font-size: 22px; font-weight: 700; margin-top: 14px; color: #16233d; }
  #groupCard .gc-details { display: grid; grid-template-columns: 90px 1fr; row-gap: 6px; margin-top: 14px; font-size: 14px; color: #16233d; }
  #groupCard .gc-details span:nth-child(odd) { color: #8a9bb5; font-weight: 600; }
  #groupCard .gc-head { font-size: 11px; font-weight: 700; color: #8a9bb5; letter-spacing: .06em; margin: 16px 0 6px; padding-top: 12px; border-top: 1px solid #eef2f8; }
  #groupCard .gc-list { max-height: 260px; overflow-y: auto; }
  #groupCard .gc-row { display: flex; gap: 10px; align-items: center; padding: 8px 10px; font-size: 14px; border-bottom: 1px solid #eef2f8; color: #16233d; }
  #groupCard .gc-row:last-child { border-bottom: none; }
  #groupCard .gc-num { width: 22px; height: 22px; border-radius: 50%; background: #eef3fa; color: #1c3a5e; font-size: 12px; font-weight: 700; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  #groupCard .gc-row.leader { background: #fffdf5; border: 1px solid #f3e3b0; border-radius: 10px; font-weight: 700; }
  #groupCard .gc-row.leader .gc-num { background: #b7791f; color: #fff; }
  #groupCard .gc-tag { margin-left: auto; font-size: 11px; color: #b7791f; font-weight: 700; }

  #scanInput { position: absolute; opacity: 0; pointer-events: none; width: 1px; height: 1px; }

  .back { margin-top: 20px; }
  .back a {
    display: block; padding: 12px 16px; background: #fff;
    border: 1px solid #dce4ef; border-radius: 12px; text-decoration: none;
    font-size: 14px; font-weight: 600; color: #16233d;
  }
  .back a:hover { background: #f4f7fb; border-color: #c7d7ec; }
  .mobile-only { display: none; }

  /* Tablet and below: one column */
  @media (max-width: 900px) { body { grid-template-columns: 1fr; } }

  /* Phone: compact mobile view */
  @media (max-width: 600px) {
    body { padding: 12px; gap: 12px; align-content: start; }
    .container { padding: 18px; max-width: none; border-radius: 14px; }
    .desktop-only { display: none; }
    .mobile-only  { display: inline; }
    #readerVisual { min-height: 220px; padding: 8px; }
    #photo        { width: 120px; height: 120px; }
    #personName   { font-size: 18px; }
    #verifyBtn    { width: 100%; padding: 14px 16px; font-size: 15px; }
    .back a       { padding: 14px 16px; }
    .logs-panel   { padding: 16px; border-radius: 14px; }
    .logs-panel h3 { font-size: 17px; margin-bottom: 10px; }
    .logs-panel th { font-size: 11px; }
    .logs-panel td { padding: 10px 0; font-size: 14px; }
  }
  </style>
</head>
<body>

<div class="container">
  <h2 id="title">Scan QR / Barcode</h2>
  <div class="dir-switch" role="group" aria-label="Scan direction">
    <button type="button" id="btnIn" class="dir-btn in">IN</button>
    <button type="button" id="btnOut" class="dir-btn out">OUT</button>
  </div>
  <div class="subtitle" id="subtitle">
    <span class="desktop-only">Hardware scanner mode</span>
    <span class="mobile-only">On a phone? Open Patrol ID Check from the dashboard</span>
  </div>

  <!-- Camera backup: opened from the dashboard sidebar (scanner_hw.php?camera=1) -->
  <div id="camPanel">
    <video id="camVideo" playsinline muted></video>
    <button type="button" id="camSwitch">Switch camera</button>
    <button type="button" class="cam-btn" id="camToggle" style="margin-top:8px">Turn camera backup off</button>
    <div id="camHint"></div>
  </div>

  <div id="readerVisual">
    <div id="suspiciousBanner" role="alert">REPEATED ACCESS DENIAL — PLEASE INVESTIGATE</div>
    <div id="idleIcon">📷</div>
    <div id="groupCard"></div>
    <img id="photo" alt="">
    <div id="alumniBadge">ALUMNI</div>
    <div id="personName"></div>
    <div id="personMeta"></div>
    <div id="badge"></div>
    <button id="verifyBtn" type="button">Verify face</button>
    <div id="statusText">Ready — point scanner at badge</div>
  </div>

  <input type="text" id="scanInput" autocomplete="off" inputmode="none">

  <button type="button" class="cam-btn" id="openDisplay" style="margin-top:16px">Open Gate Display (this computer)</button>

  <div class="back"><a href="dashboard.php">Back to Dashboard</a></div>
</div>

<div class="logs-panel">
  <h3>Recent Logs</h3>
  <table>
    <thead><tr><th>Name</th><th>Status</th><th>Time</th></tr></thead>
    <tbody id="logsBody"><tr><td colspan="3" class="logs-empty">Loading...</td></tr></tbody>
  </table>
</div>

<script src="zxing.min.js"></script>
<script src="sounds.js"></script>
<script>
const scanInput = document.getElementById('scanInput');
const box       = document.getElementById('readerVisual');
const idleIcon  = document.getElementById('idleIcon');
const photo     = document.getElementById('photo');
const nameEl    = document.getElementById('personName');
const metaEl    = document.getElementById('personMeta');
const badge     = document.getElementById('badge');
const statusEl  = document.getElementById('statusText');
const alumniEl  = document.getElementById('alumniBadge');
const bannerEl  = document.getElementById('suspiciousBanner');
const groupEl   = document.getElementById('groupCard');

/* ---------- IN / OUT switch ----------
   The guard picks the direction. The choice is remembered on this device.
   The server still checks every scan against the person's real status. */
const DIR_KEY = 'cacsScanDirection';
const btnIn   = document.getElementById('btnIn');
const btnOut  = document.getElementById('btnOut');
let SCAN_MODE = 'IN';
try { if (localStorage.getItem(DIR_KEY) === 'OUT') SCAN_MODE = 'OUT'; } catch (e) {}

function setDirection(m) {
  SCAN_MODE = m === 'OUT' ? 'OUT' : 'IN';
  btnIn.classList.toggle('active', SCAN_MODE === 'IN');
  btnOut.classList.toggle('active', SCAN_MODE === 'OUT');
  try { localStorage.setItem(DIR_KEY, SCAN_MODE); } catch (e) {}
}
btnIn.addEventListener('click', () => setDirection('IN'));
btnOut.addEventListener('click', () => setDirection('OUT'));
setDirection(SCAN_MODE);

const FLUSH_IDLE_MS = 80;       // flush buffer if scanner sends no Enter
const REASONS = { UNKNOWN_ID: 'ID not found', QR_EXPIRED: 'QR expired', QR_USED: 'QR already used', FACE_MISMATCH: 'Face mismatch', NOT_REGISTERED: 'Not registered' };
const PLACEHOLDER = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#8a9bb5" stroke-width="1.5">' +
  '<circle cx="12" cy="9" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>');

let buffer = '', scanTimer = null, resetTimer = null, busy = false;

/* ---------- Gate display (second screen) ----------
   The server saves every scan; gate_display.php polls it. This button only opens it on THIS computer.
   For another device, open gate_display.php in that device's browser instead. */
let gateWin = null;
document.getElementById('openDisplay').addEventListener('click', () => {
  if (gateWin && !gateWin.closed) { gateWin.focus(); return; }
  gateWin = window.open('gate_display.php?gate=' + (SCAN_MODE === 'OUT' ? 'out' : 'in'), 'cacsGateDisplay', 'width=900,height=700');
});

/* ---------- Sound ----------
   Uses sounds.js when it works; otherwise falls back to built-in beeps,
   so the scanner is never silent. Browsers block audio until the first
   key press or click, so the shared audio context is unlocked then. */
let audioCtx = null;
function getCtx() {
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
  } catch (e) {}
  return audioCtx;
}
// Your sound files. If they are in a folder, change the paths (e.g. 'sounds/success.wav').
// Denied scans reuse warn.wav; the suspicious-denial siren stays a built-in alarm.
const SOUND_FILES = { success: 'success.wav', warn: 'warn.wav', error: 'warn.wav' };
const wavs = {};
Object.keys(SOUND_FILES).forEach(function (k) {
  const a = new Audio(SOUND_FILES[k]);
  a.preload = 'auto';
  a.addEventListener('error', function () { a.broken = true; });   // missing file: use the beep instead
  wavs[k] = a;
});

function unlockSound() {
  getCtx();
  // Allow the .wav files to play: browsers need one user action first
  Object.keys(wavs).forEach(function (k) {
    const a = wavs[k];
    try {
      a.muted = true;
      const p = a.play();
      const done = function () { a.pause(); a.currentTime = 0; a.muted = false; };
      if (p && p.then) p.then(done, function () { a.muted = false; }); else done();
    } catch (e) { a.muted = false; }
  });
  try { if (window.Sound && Sound.unlock) Sound.unlock(); } catch (e) {}
}
scanInput.addEventListener('keydown', unlockSound, { once: true });
document.addEventListener('click', unlockSound, { once: true });

function tone(freq, start, len, type) {
  const ctx = getCtx(); if (!ctx) return;
  const o = ctx.createOscillator(), g = ctx.createGain();
  o.type = type || 'sine'; o.frequency.value = freq;
  const t = ctx.currentTime + start;
  g.gain.setValueAtTime(0.2, t); g.gain.setValueAtTime(0, t + len);
  o.connect(g); g.connect(ctx.destination);
  o.start(t); o.stop(t + len + 0.02);
}
const FALLBACK = {
  success: () => { tone(880, 0, 0.12); tone(1320, 0.13, 0.15); },
  warn:    () => { tone(600, 0, 0.12); tone(600, 0.2, 0.12); },
  error:   () => { tone(220, 0, 0.35, 'square'); }
};

// Uses sounds.js when it works, otherwise the built-in beeps
function snd(name) {
  // 1) your .wav file
  const a = wavs[name];
  if (a && !a.broken) {
    try {
      a.pause(); a.currentTime = 0;
      const p = a.play();
      if (p && p.catch) p.catch(function () { try { if (FALLBACK[name]) FALLBACK[name](); } catch (e) {} });
      return;
    } catch (e) {}
  }
  // 2) sounds.js, if it has this sound
  try { if (window.Sound && typeof Sound[name] === 'function') { Sound[name](); return; } } catch (e) {}
  // 3) built-in beep
  try { if (FALLBACK[name]) FALLBACK[name](); } catch (e) {}
}

// Alarm: uses Sound.alarm() from sounds.js if it exists, otherwise a built-in siren
function playAlarm() {
  if (window.Sound && typeof Sound.alarm === 'function') { snd('alarm'); return; }
  try { for (let i = 0; i < 6; i++) tone(i % 2 ? 660 : 990, i * 0.25, 0.22, 'square'); } catch (e) {}
}

// Group visitor card: group name, purpose, destination, leader and numbered members
function renderGroup(g, result) {
  groupEl.textContent = '';
  const add = (parent, tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    parent.appendChild(e);
    return e;
  };

  const top = add(groupEl, 'div', 'gc-top');
  add(top, 'span', 'gc-label', 'GROUP VISITOR · ' + g.size + ' PEOPLE');
  const label = ({ ENTRY: 'ENTRY', EXIT: 'EXIT', DUPLICATE: 'ALREADY SCANNED', INSIDE: 'INSIDE', NOT_INSIDE: 'NOT INSIDE' })[result] || 'DENIED';
  const pill = add(top, 'span', 'gc-badge', label);
  pill.style.background = result === 'ENTRY' ? '#16a34a' : result === 'EXIT' ? '#2563eb' : result === 'DUPLICATE' ? '#d99a0b' : '#dc2626';

  add(groupEl, 'div', 'gc-name', g.name);

  const det = add(groupEl, 'div', 'gc-details');
  if (g.purpose)     { add(det, 'span', '', 'Purpose');     add(det, 'span', '', g.purpose); }
  if (g.destination) { add(det, 'span', '', 'Destination'); add(det, 'span', '', g.destination); }

  add(groupEl, 'div', 'gc-head', 'PEOPLE');

  const list = add(groupEl, 'div', 'gc-list');
  const leader = add(list, 'div', 'gc-row leader');
  add(leader, 'span', 'gc-num', '1');
  add(leader, 'span', '', g.leader);
  add(leader, 'span', 'gc-tag', 'LEADER');

  g.members.forEach(function (m, i) {
    const row = add(list, 'div', 'gc-row');
    add(row, 'span', 'gc-num', String(i + 2));
    add(row, 'span', '', m);
  });
}

function showResult(d) {
  clearTimeout(resetTimer);
  const type = (d.result || 'DENIED').toLowerCase();       // entry | exit | denied
  box.className = type;
  idleIcon.style.display = 'none';
  bannerEl.style.display = d.suspicious ? 'block' : 'none';
  alumniEl.style.display = d.alumni ? 'inline-block' : 'none';

  const g = d.group || null;
  if (g) {
    // Group visitor: the group card replaces the photo, name and badge
    renderGroup(g, d.result);
    groupEl.style.display = 'block';
    photo.style.display = nameEl.style.display = metaEl.style.display = 'none';
    badge.style.display = 'none';
  } else {
    groupEl.style.display = 'none';
    groupEl.textContent = '';
    if (d.name) {
      photo.onerror = () => { photo.src = PLACEHOLDER; };
      photo.src = d.photo || PLACEHOLDER;
      photo.style.display = 'block';
      nameEl.textContent = d.name;
      nameEl.style.display = 'block';
      metaEl.textContent = (d.role ? d.role.toUpperCase() : '') + (d.id ? '  •  ID ' + d.id : '') +
        (d.info && d.info.length ? '\n' + d.info.join('  •  ') : '');
      metaEl.style.display = 'block';
    } else {
      photo.style.display = nameEl.style.display = metaEl.style.display = 'none';
      metaEl.textContent = d.id ? 'Code: ' + d.id : '';
      if (d.id) metaEl.style.display = 'block';
    }

    badge.textContent = ({ ENTRY: 'ENTRY', EXIT: 'EXIT', DUPLICATE: 'ALREADY SCANNED', INSIDE: 'INSIDE', NOT_INSIDE: 'NOT INSIDE' })[d.result] || 'DENIED';
    badge.style.display = 'inline-block';
  }

  verifyCode = d.id || null;
  verifyBtn.textContent = 'Verify face';
  verifyBtn.style.display = (d.has_face && verifyCode) ? 'inline-block' : 'none';
  statusEl.textContent = d.message || '';

  const okScan = (d.result === 'ENTRY' || d.result === 'EXIT' || d.result === 'INSIDE');
  if (d.suspicious) playAlarm();
  else if (okScan) snd('success');
  else if (d.result === 'DUPLICATE') snd('warn');
  else snd('error');   // invalid barcode, expired QR, denied
  if (navigator.vibrate) navigator.vibrate(okScan ? 200 : [100, 50, 100]);

  // No auto-reset: the card stays until the next scan replaces it.
}

function handleScan(raw) {
  const code = raw.trim();
  if (!code || busy) return;

  busy = true;
  clearTimeout(resetTimer);
  box.className = 'scanning';
  statusEl.textContent = 'Verifying...';

  fetch(location.pathname, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'action=scan&mode=' + encodeURIComponent(SCAN_MODE) + '&code=' + encodeURIComponent(code)
  })
  .then(r => r.json())
  .then(showResult)
  .catch(() => showResult({ result: 'DENIED', message: 'Server error, please scan again' }))
  .finally(() => { busy = false; refocus(); loadLogs(); });
}

function refocus() { scanInput.value = ''; scanInput.focus(); }

/* Recent logs panel */
const logsBody = document.getElementById('logsBody');

async function loadLogs() {
  try {
    const res = await fetch(location.pathname, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=logs'
    });
    const data = await res.json();
    if (!data.logs) return;

    logsBody.textContent = '';
    if (data.logs.length === 0) {
      const tr = logsBody.insertRow();
      const td = tr.insertCell();
      td.colSpan = 3; td.className = 'logs-empty'; td.textContent = 'No activity yet';
      return;
    }
    data.logs.forEach(l => {
      const tr = logsBody.insertRow();
      tr.insertCell().textContent = l.name;
      const badgeCell = tr.insertCell();
      const b = document.createElement('span');
      b.className = 'lbadge ' + (l.status === 'IN' ? 'in' : l.status === 'OUT' ? 'out' : 'denied');
      b.textContent = l.status;
      badgeCell.appendChild(b);
      if (l.flagged) {
        const f = document.createElement('span');
        f.className = 'lflag'; f.textContent = '⚑ FLAGGED';
        badgeCell.appendChild(f);
      }
      if (l.status === 'DENIED' && l.reason) {
        const r = document.createElement('span');
        r.className = 'lreason'; r.textContent = REASONS[l.reason] || l.reason;
        badgeCell.appendChild(r);
      }
      tr.insertCell().textContent = l.time;
    });
  } catch (e) { /* keep the last list if a refresh fails */ }
}

loadLogs();
setInterval(loadLogs, 5000);

/* Optional face verification opens on its own page */
const verifyBtn = document.getElementById('verifyBtn');
let verifyCode = null;

verifyBtn.addEventListener('click', () => {
  if (verifyCode) location.href = 'face_verify.html?code=' + encodeURIComponent(verifyCode);
});

scanInput.addEventListener('keydown', (e) => {
  if (busy) { e.preventDefault(); return; }

  if (e.key === 'Enter') {
    e.preventDefault();
    clearTimeout(scanTimer);
    const code = buffer; buffer = ''; scanInput.value = '';
    handleScan(code);
    return;
  }

  if (e.key.length === 1) buffer += e.key;

  clearTimeout(scanTimer);
  scanTimer = setTimeout(() => {
    if (buffer) { const code = buffer; buffer = ''; scanInput.value = ''; handleScan(code); }
  }, FLUSH_IDLE_MS);
});

/* ---------- Camera backup: use the laptop or phone camera when the hardware scanner is not working ----------
   Every code read here goes through the SAME handleScan() as the hardware scanner. */
const camToggle = document.getElementById('camToggle');
const camPanel  = document.getElementById('camPanel');
const camVideo  = document.getElementById('camVideo');
const camSwitch = document.getElementById('camSwitch');
const camHint   = document.getElementById('camHint');
let camStream = null, camRun = 0, camDevices = [], camSwitching = false;
let camCurrent = { id: null, facing: null };     // the camera that is running now
let camLastCode = '', camLastAt = 0;

const wait = ms => new Promise(r => setTimeout(r, ms));

function setCamButton(on) {
  camToggle.textContent = on ? 'Turn camera backup off' : 'Use camera backup (laptop)';
}

function stopStream() {
  if (camStream) camStream.getTracks().forEach(t => t.stop());
  camStream = null;
  camVideo.srcObject = null;
}

// Which camera a running stream came from
function identityOf(stream) {
  const s = stream.getVideoTracks()[0].getSettings();
  return { id: s.deviceId || null, facing: s.facingMode || null };
}

// True when two identities are the same physical camera
function sameCamera(a, b) {
  if (a.id && b.id) return a.id === b.id;
  return !!a.facing && a.facing === b.facing;
}

// Opens one camera with the given constraints. Throws if it cannot be opened.
async function openCam(videoConstraints) {
  const constraints = Object.assign({ width: { ideal: 1280 }, height: { ideal: 720 } }, videoConstraints);
  const stream = await navigator.mediaDevices.getUserMedia({ video: constraints, audio: false });
  camStream = stream;
  camVideo.srcObject = stream;
  try {
    await camVideo.play();
  } catch (e) {
    stopStream();
    throw e;
  }
  camCurrent = identityOf(stream);
}

// The camera names and IDs only appear after permission is given
async function loadCamList() {
  camDevices = (await navigator.mediaDevices.enumerateDevices())
    .filter(d => d.kind === 'videoinput' && d.deviceId);
}

async function startCam(videoConstraints) {
  stopCam(true);
  camPanel.style.display = 'block';
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    camHint.textContent = 'The camera is not available here. Open this page on localhost or https.';
    return;
  }
  const run = ++camRun;
  try {
    await wait(300);                 // give the phone time to free the previous camera
    if (run !== camRun) return;      // the user turned the camera off meanwhile
    await openCam(videoConstraints || { facingMode: { ideal: 'environment' } });
    if (run !== camRun) { stopStream(); return; }
    await loadCamList();
    camSwitch.style.display = 'inline-block';
    setCamButton(true);
    camHint.textContent = 'Hold the barcode in front of the camera.';
    camLoop(run);
  } catch (e) {
    camHint.textContent = 'Could not open the camera. Allow camera access in the browser and try again.';
  }
}

function stopCam(keepPanel) {
  camRun++;
  stopStream();
  setCamButton(false);
  if (!keepPanel) {
    camPanel.style.display = 'none';
    camSwitch.style.display = 'none';
    camHint.textContent = '';
  }
}

async function camLoop(run) {
  const useZX = !!window.ZXing;
  let detector = null, reader = null;
  if (useZX) {
    reader = new ZXing.MultiFormatReader();
    reader.setHints(new Map([[ZXing.DecodeHintType.TRY_HARDER, true]]));
  } else if ('BarcodeDetector' in window) {
    detector = new BarcodeDetector();
  } else {
    camHint.textContent = 'Barcode reading is not available. Check that zxing.min.js is next to scanner_hw.php.';
    return;
  }
  const cv = document.createElement('canvas');
  const cx = cv.getContext('2d', { willReadFrequently: true });
  let candidate = '', hits = 0, candidateAt = 0;

  while (camStream && run === camRun) {
    await wait(200);
    if (!camVideo.videoWidth || busy) continue;

    let text = '';
    try {
      if (reader) {
        const scale = Math.min(1, 960 / camVideo.videoWidth);
        cv.width  = Math.round(camVideo.videoWidth * scale);
        cv.height = Math.round(camVideo.videoHeight * scale);
        cx.drawImage(camVideo, 0, 0, cv.width, cv.height);
        const bmp = new ZXing.BinaryBitmap(new ZXing.HybridBinarizer(new ZXing.HTMLCanvasElementLuminanceSource(cv)));
        text = reader.decode(bmp).getText();
      } else {
        const found = await detector.detect(camVideo);
        if (found.length) text = found[0].rawValue;
      }
    } catch (e) { /* nothing readable in this frame */ }

    text = (text || '').trim();
    if (!text) { if (Date.now() - candidateAt > 1200) { candidate = ''; hits = 0; } continue; }

    // The same code must be read twice in a row, so a misread bar never counts as a denied scan
    if (text === candidate) hits++; else { candidate = text; hits = 1; }
    candidateAt = Date.now();
    if (hits < 2) continue;
    candidate = ''; hits = 0;

    // Holding the same card in front of the camera must not scan it again and again
    if (text === camLastCode && Date.now() - camLastAt < 4000) continue;
    camLastCode = text; camLastAt = Date.now();
    handleScan(text);
  }
}

camToggle.addEventListener('click', () => { camStream ? stopCam(false) : startCam(); });

// Switch camera: tries the other side (front/back) first, then the other cameras in the list.
// A camera only counts as switched if it is really different from the one running now.
camSwitch.addEventListener('click', async () => {
  if (camSwitching) return;
  camSwitching = true;
  camSwitch.disabled = true;
  camHint.textContent = 'Switching camera...';
  const previous = { ...camCurrent };
  const previousConstraints = previous.id
    ? { deviceId: { exact: previous.id } }
    : { facingMode: { ideal: previous.facing || 'environment' } };
  try {
    const candidates = [];
    const otherSide = previous.facing === 'user' ? 'environment' : 'user';
    candidates.push({ facingMode: { exact: otherSide } });
    camDevices.forEach(d => {
      if (d.deviceId !== previous.id) candidates.push({ deviceId: { exact: d.deviceId } });
    });

    for (const c of candidates) {
      stopCam(true);
      const run = camRun;
      try {
        await wait(300);
        await openCam(c);
        if (sameCamera(previous, camCurrent)) { stopStream(); continue; }   // same lens: try the next
        camHint.textContent = 'Hold the barcode in front of the camera.';
        camLoop(run);
        return;
      } catch (e) {
        // this camera did not open: try the next one
      }
    }
    // Nothing else opened: go back to the camera that was running
    camHint.textContent = 'No other camera could be opened. Going back to the previous one.';
    await startCam(previousConstraints);
  } finally {
    camSwitching = false;
    camSwitch.disabled = false;
  }
});

window.addEventListener('pagehide', () => stopCam(false));

document.addEventListener('click', refocus);
window.addEventListener('load', refocus);
setInterval(() => { if (document.activeElement !== scanInput) refocus(); }, 500);

/* Opened from the dashboard's "Camera Backup" link */
if (new URLSearchParams(location.search).get('camera') === '1') startCam();
</script>
</body>
</html>