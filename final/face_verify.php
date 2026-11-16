<?php
session_start();
include 'db.php';
include_once 'auth.php';

// Face check is for security personnel at the gate or on patrol. Anyone else is sent to the login page.
require_auth($conn, ['personnel']);

define('FACE_MATCH_THRESHOLD', 0.45);   // lower = stricter (0.6 is face-api's default)

// ============================================================
// HELPERS
// ============================================================

function pageStart($title) {
  return <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$title</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; padding: 24px; overflow: hidden;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #fafbfd;
      display: flex; justify-content: center; align-items: center;
    }
    .container {
      width: 100%; max-width: 360px; padding: 30px; background: #fff;
      border-radius: 18px; border: 1px solid #dce4ef;
      box-shadow: 0 1px 3px rgba(22,58,94,0.05);
      text-align: center; color: #16233d;
    }
    h2 { font-size: 18px; font-weight: 600; margin: 0 0 6px; }
    .sub { font-size: 13px; color: #6b7a94; margin: 0 0 4px; line-height: 1.5; }

    /* Status badge: the one memorable element on every result page */
    .badge {
      width: 64px; height: 64px; margin: 0 auto 16px;
      border-radius: 50%; border: 2px solid;
      display: flex; align-items: center; justify-content: center;
    }
    .badge svg {
      width: 30px; height: 30px; fill: none; stroke: currentColor;
      stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;
    }
    .badge.ok   { color: #16a34a; border-color: #16a34a; background: #e8f8ef; box-shadow: 0 0 0 6px rgba(22,163,74,0.10); }
    .badge.err  { color: #dc2626; border-color: #dc2626; background: #fdeaea; box-shadow: 0 0 0 6px rgba(220,38,38,0.10); }
    .badge.warn { color: #d99a0b; border-color: #f0b429; background: #fffbeb; box-shadow: 0 0 0 6px rgba(240,180,41,0.16); }

    img {
      width: 120px; height: 120px; border-radius: 14px; object-fit: cover;
      margin: 0 auto 14px; display: block; border: 2px solid #16a34a;
    }

    .code-chip {
      display: inline-block; margin-top: 12px; padding: 3px 10px;
      border-radius: 999px; background: #eef3fa; border: 1px solid #dce4ef;
      font-size: 12px; font-weight: 600; color: #1c3a5e;
    }

    .info { margin-top: 16px; text-align: left; }
    .row {
      display: flex; justify-content: space-between; gap: 16px;
      padding: 9px 0; border-bottom: 1px solid #eef2f8; font-size: 13px;
    }
    .row:last-child { border-bottom: 0; }
    .row span { color: #8a9bb5; }
    .row strong { color: #16233d; font-weight: 600; text-align: right; }

    .pill {
      display: inline-block; margin-top: 16px; padding: 6px 16px;
      border-radius: 999px; font-size: 13px; font-weight: 600;
    }
    .pill.ok  { background: #e8f8ef; color: #16a34a; }
    .pill.err { background: #fdeaea; color: #dc2626; }

    .links { margin-top: 20px; display: flex; flex-direction: column; gap: 8px; }
    .links a {
      display: block; padding: 12px 16px;
      background: #fff; color: #16233d;
      border: 1px solid #dce4ef; border-radius: 12px;
      font-size: 14px; font-weight: 600; text-decoration: none;
      transition: transform .15s, background .15s, border-color .15s, box-shadow .15s;
    }
    .links a:hover {
      transform: translateY(-2px);
      background: #fffdf5;
      border-color: #f0b429;
      box-shadow: 0 8px 24px rgba(240,180,41,0.25);
    }
    .links a:focus-visible { outline: 2px solid #f0b429; outline-offset: 2px; }

    @media (prefers-reduced-motion: reduce) {
      .links a { transition: none; }
    }
  </style>
</head>
<body>
<div class="container">
HTML;
}

function pageEnd() {
  return "</div></body></html>";
}

// Status badge: $state is 'ok' (check), 'err' (cross) or 'warn' (magnifier = not found)
function statusBadge($state) {
  $icons = [
    'ok'   => '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    'err'  => '<path d="M6 6l12 12M18 6L6 18"/>',
    'warn' => '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.2-4.2"/>',
  ];
  return "<div class='badge $state' aria-hidden='true'><svg viewBox='0 0 24 24'>" . $icons[$state] . "</svg></div>";
}

function infoRow($label, $value) {
  return "<div class='row'><span>" . htmlspecialchars($label) . "</span><strong>" . htmlspecialchars($value) . "</strong></div>";
}

// Success page only (failures use renderError so the owner's info is never exposed)
function renderResult($user, $statusMessage, $code = '') {
  $imgSrc = $user['face_image'] ?? '';
  if ($imgSrc !== '' && !str_starts_with($imgSrc, 'data:image')) {
    $imgSrc = 'data:image/jpeg;base64,' . $imgSrc;
  }

  $name = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
  $msg  = htmlspecialchars(trim($statusMessage));

  echo pageStart('Verification Result');
  if ($imgSrc !== '') {
    echo '<img src="' . htmlspecialchars($imgSrc) . '" alt="User photo">';
  } else {
    echo statusBadge('ok');
  }
  echo "<h2>Verification result</h2>";
  echo "<div class='info'>"
    . infoRow('Name', $name)
    . infoRow('ID', $user['id_number'] ?? '')
    . infoRow('Role', $user['role'] ?? '')
    . infoRow('Course', $user['course'] ?? '')
    . infoRow('Department', $user['department'] ?? '')
    . "</div>
  <div class='pill ok'>$msg</div>
  <div class='links'>
    <a href='scanner_hw.php'>Back to Scanner</a>
    <a href='dashboard.php'>Back to Dashboard</a>
  </div>";
  echo pageEnd();
}

// Error / not-found page: shows NO owner details or photo, only the message and navigation links.
// $state: 'err' (red) for failures, 'warn' (gold) for "not found" style notices.
function renderError($message, $code = '', $allowRetry = false, $title = 'Verification failed', $state = 'err', $showCode = false) {
  $msg = htmlspecialchars($message);
  echo pageStart($title);
  echo statusBadge($state);
  echo "<h2>" . htmlspecialchars($title) . "</h2>
  <p class='sub'>$msg</p>";
  if ($showCode && $code !== '') {
    echo "<span class='code-chip'>Code " . htmlspecialchars($code) . "</span>";
  }
  echo "<div class='links'>";
  if ($allowRetry) {
    echo "<a href='face_verify.html?code=" . urlencode($code) . "'>Try again</a>";
  }
  echo "<a href='scanner_hw.php'>Back to Scanner</a>
    <a href='dashboard.php'>Back to Dashboard</a>
  </div>";
  echo pageEnd();
}

// Insert a log row unless one was written for this person or visitor in the last 5 seconds
function writeLog($conn, $event, $personType, $personId, $visitorId, $idNumber, $name) {
  $column = $visitorId ? 'visitor_id' : 'person_id';
  $id     = $visitorId ? (int)$visitorId : (int)$personId;

  $dup = $conn->prepare("SELECT id FROM access_logs WHERE $column = ? AND event <> 'DENIED' AND logged_at >= NOW() - INTERVAL 5 SECOND LIMIT 1");
  $dup->bind_param("i", $id);
  $dup->execute();
  if ($dup->get_result()->num_rows === 0) {
    $staffId = $_SESSION['staff_ids']['personnel'] ?? null;
    $guard   = mb_substr((string)($_SESSION['security_username'] ?? ''), 0, 50);
    $log = $conn->prepare("INSERT INTO access_logs (event, person_type, person_id, visitor_id, id_number, name_snapshot, staff_id, guard_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $log->bind_param("ssiissis", $event, $personType, $personId, $visitorId, $idNumber, $name, $staffId, $guard);
    $log->execute();
  }
}

// Flip the person's IN/OUT status, log it, and show the result page
function checkInUser($conn, $user, $code) {
  $newStatus = ($user['status'] === 'IN') ? 'OUT' : 'IN';
  $type      = ($newStatus === 'IN') ? 'ENTRY' : 'EXIT';
  $personId  = (int)$user['id'];

  $update = $conn->prepare("UPDATE people SET status = ? WHERE id = ?");
  $update->bind_param("si", $newStatus, $personId);
  $update->execute();

  writeLog($conn, $type, strtolower((string)$user['role']), $personId, null, $user['id_number'], $user['first_name'] . ' ' . $user['last_name']);
  renderResult($user, "$newStatus SUCCESS", $code);
}

// ============================================================
// INPUT
// ============================================================

$code           = trim($_POST['code'] ?? $_POST['barcode'] ?? '');
$descriptorJson = $_POST['face_descriptor'] ?? '';

if ($code === '') {
  renderError("No code was received. Scan the badge again.", '', false, 'No code received', 'warn');
  exit;
}

// ============================================================
// VISITORS FIRST
// ============================================================

$stmt = $conn->prepare("SELECT * FROM visitors WHERE qr_code = ?");
$stmt->bind_param("s", $code);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
  $visitor   = $result->fetch_assoc();
  $visitorId = (int)$visitor['id'];
  $newStatus = ($visitor['status'] === 'IN') ? 'OUT' : 'IN';
  $type      = ($newStatus === 'IN') ? 'ENTRY' : 'EXIT';

  $update = $conn->prepare("UPDATE visitors SET status = ? WHERE id = ?");
  $update->bind_param("si", $newStatus, $visitorId);
  $update->execute();

  writeLog($conn, $type, 'visitor', null, $visitorId, 'V' . $visitorId, $visitor['name']);

  echo pageStart('Visitor Verified');
  echo statusBadge('ok');
  echo "<h2>Visitor verified</h2>
  <p class='sub'>Visitor pass accepted.</p>
  <div class='info'>"
    . infoRow('Name', $visitor['name'])
    . infoRow('Purpose', $visitor['purpose'])
    . infoRow('Destination', $visitor['destination'])
    . "</div>
  <div class='pill ok'>$newStatus SUCCESS</div>
  <div class='links'>
    <a href='scanner_hw.php'>Back to Scanner</a>
    <a href='dashboard.php'>Back to Dashboard</a>
  </div>";
  echo pageEnd();
  exit;
}

// ============================================================
// PEOPLE (face data comes from face_data)
// ============================================================

$stmt = $conn->prepare("
  SELECT p.*, fd.descriptor AS face_descriptor, fd.image AS face_image
  FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id
  WHERE p.id_number = ?
");
$stmt->bind_param("s", $code);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
  renderError("No user or visitor matches this code.", $code, false, 'Not found', 'warn', true);
  exit;
}

$user = $result->fetch_assoc();

// Barcode only (no face descriptor sent)
if ($descriptorJson === '') {
  checkInUser($conn, $user, $code);
  exit;
}

// ============================================================
// FACE MATCH
// ============================================================

// Lock out after 5 failed attempts within 5 minutes
$_SESSION['face_fails'] = array_filter($_SESSION['face_fails'] ?? [], fn($t) => $t > time() - 300);
if (count($_SESSION['face_fails']) >= 5) {
  renderError("Too many failed attempts. Please wait a few minutes.", $code, false);
  exit;
}

$descriptor = json_decode($descriptorJson, true);
$stored     = json_decode($user['face_descriptor'] ?? '', true);

if (!is_array($descriptor) || !is_array($stored) || count($descriptor) !== 128 || count($stored) !== 128) {
  renderError("Face data invalid. Please re-register.", $code, false);
  exit;
}

function euclid($a, $b) {
  $s = 0.0;
  for ($i = 0; $i < 128; $i++) { $d = $a[$i] - $b[$i]; $s += $d * $d; }
  return sqrt($s);
}

$distance = euclid($descriptor, $stored);
error_log("face_verify: id=$code distance=" . round($distance, 3));

// Reject if a DIFFERENT registered person matches this face better than the scanned ID does
$matchesSomeoneElse = false;
$others = $conn->query("
  SELECT p.id_number, fd.descriptor
  FROM face_data fd JOIN people p ON p.id = fd.person_id
  WHERE fd.descriptor IS NOT NULL AND fd.descriptor <> ''
");
if ($others) {
  while ($o = $others->fetch_assoc()) {
    if ((string)$o['id_number'] === (string)$code) continue;
    $od = json_decode($o['descriptor'], true);
    if (!is_array($od) || count($od) !== 128) continue;
    if (euclid($descriptor, $od) < $distance) { $matchesSomeoneElse = true; break; }
  }
  $others->free();
}

if ($distance <= FACE_MATCH_THRESHOLD && !$matchesSomeoneElse) {
  checkInUser($conn, $user, $code);
  exit;
}

// FAILED: error page (no owner photo/details), with a manual retry link
$_SESSION['face_fails'][] = time();
renderError("Face doesn't match.", $code, true);