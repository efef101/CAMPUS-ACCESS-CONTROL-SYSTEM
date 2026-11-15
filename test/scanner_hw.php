<?php
session_start();

// Same login check as dashboard.php
if (!isset($_SESSION['security_logged_in'])) {
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    http_response_code(401);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['result' => 'DENIED', 'message' => 'Session expired. Please log in again.']);
  } else {
    header("Location: login.php");
  }
  exit;
}
define('FACE_MATCH_THRESHOLD', 0.45);   // lower = stricter (0.6 is face-api's default)

// ============================================================
// HELPERS
// ============================================================

function out(array $a) { echo json_encode($a, JSON_UNESCAPED_UNICODE); exit; }

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

function recentlyLogged($conn, $logId) {
  $q = $conn->prepare("SELECT id FROM logs WHERE id_number = ? AND status <> 'DENIED' AND timestamp >= NOW() - INTERVAL 5 SECOND");
  $q->bind_param("s", $logId);
  $q->execute();
  return $q->get_result()->num_rows > 0;
}

// Saves the scan AND which guard made it (scanned_by / scanned_by_name)
function writeLog($conn, $logId, $name, $role, $status, $type) {
  $by  = mb_substr((string)($_SESSION['security_username'] ?? ''), 0, 50);
  $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type, scanned_by, scanned_by_name) VALUES (?, ?, ?, ?, ?, ?, ?)");
  $log->bind_param("sssssss", $logId, $name, $role, $status, $type, $by, $by);
  $log->execute();
}

// ============================================================
// AJAX HANDLER (scan + patrol check + optional face compare)
// ============================================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  header('Content-Type: application/json; charset=utf-8');
  include 'db.php';
  require_once __DIR__ . '/scan_security.php';
  $action = $_POST['action'] ?? 'scan';
  $code   = trim($_POST['code'] ?? $_POST['barcode'] ?? '');

  // ---------- RECENT LOGS (for the panel next to the scanner) ----------
  if ($action === 'logs') {
    session_write_close();
    $logs = [];
    $r = $conn->query("SELECT name, status, reason, flagged, timestamp FROM logs ORDER BY timestamp DESC, id DESC LIMIT 10");
    while ($r && $row = $r->fetch_assoc()) {
      $logs[] = [
        'name'    => $row['name'],
        'status'  => $row['status'],
        'reason'  => $row['reason'],
        'flagged' => (int)$row['flagged'] === 1,
        'time'    => date('M j, g:i A', strtotime($row['timestamp'])),
      ];
    }
    out(['logs' => $logs]);
  }

  // ---------- PATROL CHECK (read-only: never changes status or writes IN/OUT logs) ----------
  // Used by scanner_mobile.php when a roving guard checks someone's ID on campus.
  if ($action === 'check') {
    if ($code === '') {
      out(['result' => 'DENIED', 'message' => 'No code received. Scan the ID again.']);
    }

    // Visitor?
    $stmt = $conn->prepare("SELECT * FROM visitors WHERE qr_code = ?");
    $stmt->bind_param("s", $code);
    $stmt->execute();
    $v = $stmt->get_result()->fetch_assoc();

    if ($v) {
      $inside  = ($v['status'] === 'IN');
      $expired = !empty($v['expires_at']) && strtotime($v['expires_at']) < time();
      out([
        'result'   => $inside ? 'INSIDE' : 'NOT_INSIDE',
        'name'     => $v['name'],
        'role'     => 'Visitor',
        'id'       => null,
        'photo'    => null,
        'has_face' => false,
        'info'     => infoList([$v['purpose'] ?? '', $v['destination'] ?? '']),
        'message'  => $inside
          ? ($expired ? 'Visitor is inside but the QR has EXPIRED' : 'Visitor is registered as inside')
          : 'Visitor is NOT checked in. Possible unauthorized entry.',
      ]);
    }

    // User?
    $stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
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

    $stmt = $conn->prepare("SELECT first_name, last_name, role, face_descriptor FROM users WHERE id_number = ?");
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
    $others = $conn->query("SELECT id_number, face_descriptor FROM users WHERE face_descriptor IS NOT NULL AND face_descriptor <> ''");
    if ($others) {
      while ($o = $others->fetch_assoc()) {
        if ((string)$o['id_number'] === (string)$code) continue;
        $od = json_decode($o['face_descriptor'], true);
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
      $rev = $conn->prepare("UPDATE users SET status = ? WHERE id_number = ? AND status = ?");
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
    $event = record_denial($conn, $code, $who, (string)$row['role'], 'FACE_MISMATCH');
    out(['match' => false, 'name' => $who, 'reverted' => $reverted, 'message' => $message, 'suspicious' => $event['suspicious']]);
  }

  // ---------- SCAN ----------
  if ($code === '') {
    out(['result' => 'DENIED', 'message' => 'No code received. Scan the badge again.']);
  }

  // Visitors first
  $stmt = $conn->prepare("SELECT * FROM visitors WHERE qr_code = ?");
  $stmt->bind_param("s", $code);
  $stmt->execute();
  $visitor = $stmt->get_result()->fetch_assoc();

  if ($visitor) {
    $person = [
      'name'     => $visitor['name'],
      'role'     => 'Visitor',
      'id'       => null,
      'photo'    => null,
      'has_face' => false,
      'info'     => infoList([$visitor['purpose'] ?? '', $visitor['destination'] ?? '']),
    ];
    $logId   = 'V' . $visitor['id'];
    $isEntry = ($visitor['status'] !== 'IN');

    // Expiry only blocks ENTRY; visitors already inside can always leave
    if ($isEntry && !empty($visitor['expires_at']) && strtotime($visitor['expires_at']) < time()) {
      $event = record_denial($conn, $logId, $visitor['name'], 'Visitor', 'QR_EXPIRED');
      out($person + ['result' => 'DENIED', 'message' => 'QR expired', 'suspicious' => $event['suspicious']]);
    }
    if (recentlyLogged($conn, $logId)) {
      out($person + ['result' => 'DUPLICATE', 'message' => 'Already scanned a moment ago']);
    }

    $to   = $isEntry ? 'IN' : 'OUT';
    $type = $isEntry ? 'ENTRY' : 'EXIT';

    // Atomic toggle: only succeeds if the status hasn't changed since we read it
    $upd = $conn->prepare("UPDATE visitors SET status = ? WHERE id = ? AND status <=> ?");
    $upd->bind_param("sis", $to, $visitor['id'], $visitor['status']);
    $upd->execute();
    if ($upd->affected_rows === 0) {
      out($person + ['result' => 'DENIED', 'message' => 'Duplicate scan, please scan again']);
    }

    writeLog($conn, $logId, $visitor['name'], 'Visitor', $to, $type);
    out($person + ['result' => $type, 'message' => $isEntry ? 'Entry granted' : 'Exit recorded']);
  }

  // Then users
  $stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
  $stmt->bind_param("s", $code);
  $stmt->execute();
  $user = $stmt->get_result()->fetch_assoc();

  if (!$user) {
    $event = record_denial($conn, $code, $code, 'Unknown', 'UNKNOWN_ID');
    out(['result' => 'DENIED', 'message' => 'ID not found', 'id' => $code, 'suspicious' => $event['suspicious']]);
  }

  $name   = trim($user['first_name'] . ' ' . $user['last_name']);
  $person = [
    'name'     => $name,
    'role'     => $user['role'],
    'id'       => $user['id_number'],
    'photo'    => faceSrc($user['face_image'] ?? ''),
    'has_face' => !empty($user['face_descriptor']),
    'alumni'   => strtolower(trim((string)$user['role'])) === 'alumni',
    'info'     => infoList([$user['course'] ?? '', $user['department'] ?? '', $user['position'] ?? '']),
  ];
  $logId   = $user['id_number'];
  $isEntry = ($user['status'] !== 'IN');

  // Not registered yet: the admin added the account, but no face was captured at registration
  if (trim((string)($user['face_descriptor'] ?? '')) === '') {
    $event = record_denial($conn, $code, $name, (string)$user['role'], 'NOT_REGISTERED');
    out($person + ['result' => 'DENIED', 'message' => 'Not registered yet. Complete registration first.', 'suspicious' => $event['suspicious']]);
  }

  if (recentlyLogged($conn, $logId)) {
    out($person + ['result' => 'DUPLICATE', 'message' => 'Already scanned a moment ago']);
  }

  $to   = $isEntry ? 'IN' : 'OUT';
  $type = $isEntry ? 'ENTRY' : 'EXIT';

  $upd = $conn->prepare("UPDATE users SET status = ? WHERE id_number = ? AND status <=> ?");
  $upd->bind_param("sss", $to, $code, $user['status']);
  $upd->execute();
  if ($upd->affected_rows === 0) {
    out($person + ['result' => 'DENIED', 'message' => 'Duplicate scan, please scan again']);
  }

  writeLog($conn, $logId, $name, $user['role'], $to, $type);
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

  .mobile-btn {
    display: block; margin-bottom: 16px; padding: 12px 16px; background: #16233d; color: #fff;
    border-radius: 12px; text-decoration: none; font-size: 14px; font-weight: 600;
  }
  .mobile-btn:hover { background: #22345a; }

  /* Camera backup (laptop webcam) */
  .cam-btn {
    display: block; width: 100%; margin-bottom: 16px; padding: 12px 16px; background: #fff; color: #16233d;
    border: 1px solid #c7d7ec; border-radius: 12px; font: 600 14px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; cursor: pointer;
  }
  .cam-btn:hover { background: #f4f7fb; }
  #camPanel { display: none; margin-bottom: 16px; }
  #camVideo { width: 100%; max-height: 260px; border-radius: 12px; background: #0f2440; object-fit: cover; }
  #camSwitch { display: none; margin-top: 8px; padding: 8px 14px; background: #fff; color: #16233d; border: 1px solid #c7d7ec; border-radius: 10px; font: 600 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; cursor: pointer; }
  #camHint { font-size: 12px; color: #6b7a94; margin-top: 8px; }

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
    .mobile-btn   { padding: 16px; font-size: 16px; }
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
  <div class="subtitle" id="subtitle">
    <span class="desktop-only">Hardware scanner mode</span>
    <span class="mobile-only">On a phone? Tap Patrol Check below to use the camera</span>
  </div>

  <a class="mobile-btn" href="mobile_scanning.php">Camera ID Check (For Patrol)</a>

  <!-- Backup when the hardware scanner is broken: uses the laptop webcam -->
  <button type="button" class="cam-btn desktop-only" id="camToggle">Camera Backup Scanner</button>
  <div id="camPanel">
    <video id="camVideo" playsinline muted></video>
    <button type="button" id="camSwitch">Switch camera</button>
    <div id="camHint"></div>
  </div>

  <div id="readerVisual">
    <div id="suspiciousBanner" role="alert">REPEATED ACCESS DENIAL — PLEASE INVESTIGATE</div>
    <div id="idleIcon">📷</div>
    <img id="photo" alt="">
    <div id="alumniBadge">ALUMNI</div>
    <div id="personName"></div>
    <div id="personMeta"></div>
    <div id="badge"></div>
    <button id="verifyBtn" type="button">Verify face</button>
    <div id="statusText">Ready — point scanner at badge</div>
  </div>

  <input type="text" id="scanInput" autocomplete="off" inputmode="none">

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

const FLUSH_IDLE_MS = 80;       // flush buffer if scanner sends no Enter
const REASONS = { UNKNOWN_ID: 'ID not found', QR_EXPIRED: 'QR expired', FACE_MISMATCH: 'Face mismatch', NOT_REGISTERED: 'Not registered' };
const PLACEHOLDER = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#8a9bb5" stroke-width="1.5">' +
  '<circle cx="12" cy="9" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>');

let buffer = '', scanTimer = null, resetTimer = null, busy = false;

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

function showResult(d) {
  clearTimeout(resetTimer);
  const type = (d.result || 'DENIED').toLowerCase();       // entry | exit | denied
  box.className = type;
  idleIcon.style.display = 'none';
  bannerEl.style.display = d.suspicious ? 'block' : 'none';
  alumniEl.style.display = d.alumni ? 'inline-block' : 'none';

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
    body: 'action=scan&code=' + encodeURIComponent(code)
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

/* ---------- Camera backup: use the laptop webcam when the hardware scanner is not working ----------
   Every code read here goes through the SAME handleScan() as the hardware scanner,
   so entry/exit, denials, flags and logs behave exactly the same. */
const camToggle = document.getElementById('camToggle');
const camPanel  = document.getElementById('camPanel');
const camVideo  = document.getElementById('camVideo');
const camSwitch = document.getElementById('camSwitch');
const camHint   = document.getElementById('camHint');
let camStream = null, camRun = 0, camDevices = [], camIndex = 0;
let camLastCode = '', camLastAt = 0;

async function startCam(deviceId) {
  stopCam(true);
  camPanel.style.display = 'block';
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    camHint.textContent = 'The camera is not available here. Open this page on localhost or https.';
    return;
  }
  try {
    const constraints = { width: { ideal: 1280 }, height: { ideal: 720 } };
    if (deviceId) constraints.deviceId = { exact: deviceId };
    else constraints.facingMode = { ideal: 'environment' };
    camStream = await navigator.mediaDevices.getUserMedia({ video: constraints, audio: false });
    camVideo.srcObject = camStream;
    await camVideo.play();

    // list the cameras (the names only appear after permission is given)
    camDevices = (await navigator.mediaDevices.enumerateDevices()).filter(d => d.kind === 'videoinput');
    const cur = camStream.getVideoTracks()[0].getSettings().deviceId;
    const at = camDevices.findIndex(d => d.deviceId === cur);
    camIndex = at >= 0 ? at : 0;
    camSwitch.style.display = camDevices.length > 1 ? 'inline-block' : 'none';

    camToggle.textContent = 'Turn camera backup off';
    camHint.textContent = 'Hold the barcode in front of the camera.';
    camLoop(++camRun);
  } catch (e) {
    camHint.textContent = 'Could not open the camera. Allow camera access in the browser and try again.';
  }
}

function stopCam(keepPanel) {
  camRun++;
  if (camStream) camStream.getTracks().forEach(t => t.stop());
  camStream = null;
  camVideo.srcObject = null;
  camToggle.textContent = 'Use camera backup (laptop)';
  camSwitch.style.display = 'none';
  if (!keepPanel) { camPanel.style.display = 'none'; camHint.textContent = ''; }
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
    await new Promise(r => setTimeout(r, 200));
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
camSwitch.addEventListener('click', () => {
  if (camDevices.length < 2) return;
  camIndex = (camIndex + 1) % camDevices.length;
  startCam(camDevices[camIndex].deviceId);
});
window.addEventListener('pagehide', () => stopCam(false));

document.addEventListener('click', refocus);
window.addEventListener('load', refocus);
setInterval(() => { if (document.activeElement !== scanInput) refocus(); }, 500);
</script>
</body>
</html>