<?php
// Step 1 (barcode only): does this ID exist? No personal details returned.
// Step 2 (barcode + birthdate): verify, then return details.
session_start();
include 'db.php';
header('Content-Type: application/json; charset=utf-8');

function out($code, $arr) { http_response_code($code); echo json_encode($arr); exit; }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(405, ['error' => 'Method not allowed']);

// ===== RATE LIMIT: 30 requests per minute per session =====
$now = time();
$_SESSION['lookup_requests'] = array_values(array_filter(
  $_SESSION['lookup_requests'] ?? [],
  fn($t) => $t > $now - 60
));
if (count($_SESSION['lookup_requests']) >= 30) out(429, ['error' => 'Too many lookups. Wait a minute.']);
$_SESSION['lookup_requests'][] = $now;

// ===== INPUT =====
$data      = json_decode(file_get_contents('php://input'), true);
$code      = trim($data['barcode']   ?? '');
$birthdate = trim($data['birthdate'] ?? '');

if (!preg_match('/^[0-9]{1,8}$/', $code)) {
  out(400, ['error' => 'Unreadable barcode. Try again or type the ID number.']);
}

// ===== STEP 1: ID CHECK ONLY (no birthdate sent) =====
if ($birthdate === '') {
  $stmt = $conn->prepare("
    SELECT (fd.descriptor IS NOT NULL AND fd.descriptor <> '') AS has_face
    FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id
    WHERE p.id_number = ? LIMIT 1
  ");
  $stmt->bind_param("s", $code);
  $stmt->execute();
  $hasFace = 0;
  $stmt->bind_result($hasFace);
  $found = $stmt->fetch();
  $stmt->close();

  if (!$found) out(404, ['error' => 'ID not found. Ask the administrator to add you first.']);
  out(200, ['found' => true, 'has_face' => (bool)$hasFace]);   // no name or other details
}

// ===== STEP 2: BIRTHDATE VERIFICATION =====
if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $birthdate, $m) || !checkdate((int)$m[2], (int)$m[3], (int)$m[1])) {
  out(400, ['error' => 'Enter a valid date of birth.']);
}

// Failed attempts in the last 15 min (per IP and per ID), stored in login_attempts with scope 'lookup'
$ip = $_SERVER['REMOTE_ADDR'] ?? '';

function failCount($conn, $col, $val) {
  $col = ($col === 'ip') ? 'ip' : 'identifier';   // whitelist
  $n = 0;
  $s = $conn->prepare("SELECT COUNT(*) FROM login_attempts WHERE scope = 'lookup' AND $col = ? AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
  if (!$s) { error_log("login_attempts query failed: " . $conn->error); return 0; }
  $s->bind_param("s", $val);
  $s->execute();
  $s->bind_result($n);
  $s->fetch();
  $s->close();
  return (int)$n;
}

if (failCount($conn, 'ip', $ip) >= 5 || failCount($conn, 'identifier', $code) >= 5) {
  out(429, ['error' => 'Too many failed attempts. Try again in 15 minutes or ask the administrator.']);
}

$stmt = $conn->prepare("
  SELECT p.id, p.first_name, p.last_name, p.birthdate, p.role, p.course, p.department,
         (fd.descriptor IS NOT NULL AND fd.descriptor <> '') AS has_face
  FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id
  WHERE p.id_number = ? LIMIT 1
");
$stmt->bind_param("s", $code);
$stmt->execute();
$stmt->bind_result($pid, $fn, $ln, $dbBirth, $role, $course, $dept, $hasFace);
$found = $stmt->fetch();
$stmt->close();

$verified = $found && hash_equals(substr((string)$dbBirth, 0, 10), $birthdate);

if (!$verified) {
  unset($_SESSION['scan_barcode'], $_SESSION['verified_at']);
  $log = $conn->prepare("INSERT INTO login_attempts (scope, ip, identifier) VALUES ('lookup', ?, ?)");
  if ($log) {
    $log->bind_param("ss", $ip, $code);
    $log->execute();
    $log->close();
  }
  out(401, ['error' => 'Date of birth does not match our records.']);
}

if ($hasFace) {
  unset($_SESSION['scan_barcode'], $_SESSION['verified_at']);
  out(200, ['found' => true, 'has_face' => true, 'name' => "$fn $ln"]);
}

session_regenerate_id(true);
$_SESSION['scan_barcode'] = $code;
$_SESSION['verified_at']  = time();

out(200, [
  'found'      => true,
  'has_face'   => false,
  'barcode'    => $code,
  'name'       => "$fn $ln",
  'role'       => $role,
  'course'     => $course,
  'department' => $dept,
]);