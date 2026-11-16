<?php
session_start();
include 'db.php';

// Version of the privacy notice shown on the registration page.
// Change this string whenever the notice wording changes, and update the same value in the page's JavaScript.
define('CONSENT_VERSION', '2026-10-v1');
define('FACE_MATCH_THRESHOLD', 0.5);   // lower = stricter

// ===== GET JSON DATA =====
$data = json_decode(file_get_contents("php://input"), true);
if (!$data) {
  die("❌ Invalid data received.");
}

// ===== CONSENT (checked first: no face data is processed without it) =====
if (($data['consent'] ?? false) !== true) {
  die("❌ Consent is required to register your face. Please read the privacy notice and tick the consent box.");
}
if (!hash_equals(CONSENT_VERSION, (string)($data['consent_version'] ?? ''))) {
  die("❌ The privacy notice was updated. Please reload the page and read it again.");
}

$barcode        = trim($data['barcode']         ?? '');
$descriptorJson = $data['face_descriptor']      ?? '';
$face_image     = $data['face_image']           ?? '';   // base64 image
$livenessToken  = $data['liveness_token']       ?? '';

// ===== LIVENESS VERIFICATION =====
$lv = $_SESSION['liveness'] ?? null;

if (!$lv || $livenessToken === '' || !hash_equals($lv['token'], (string)$livenessToken)) {
  die("❌ Liveness check required. Please capture your face again.");
}

$age = time() - $lv['issued_at'];
if ($age > 300) {
  unset($_SESSION['liveness']);
  die("❌ Liveness check expired. Please capture your face again.");
}
if ($age < 2) {
  die("❌ Submission too fast. Please try again.");
}

// ===== ID MUST MATCH THE ONE VERIFIED IN THIS SESSION =====
if (!preg_match('/^[0-9]{1,8}$/', $barcode)) {
  die("❌ Invalid ID.");
}
if (!isset($_SESSION['scan_barcode']) || !hash_equals($_SESSION['scan_barcode'], $barcode)) {
  die("❌ Please scan your ID again.");
}
if (empty($_SESSION['verified_at']) || time() - $_SESSION['verified_at'] > 900) {
  die("❌ Verification expired. Please scan your ID again.");
}

// ===== FACE VALIDATION =====
$descriptor = json_decode($descriptorJson, true);

function isValidFaceDescriptor($descriptor) {
  if (!is_array($descriptor) || count($descriptor) !== 128) return false;
  foreach ($descriptor as $value) {
    if (!is_numeric($value)) return false;
  }
  return true;
}

if (!isValidFaceDescriptor($descriptor)) {
  die("❌ Face not captured properly. Please capture again.");
}

// ===== FACE IMAGE VALIDATION =====
if ($face_image === '') {
  die("❌ Face image missing.");
}
if (!preg_match('#^data:image/jpeg;base64,([A-Za-z0-9+/=]+)$#', $face_image, $m)) {
  die("❌ Invalid face image format.");
}
$raw = base64_decode($m[1], true);
if ($raw === false || strlen($raw) > 2 * 1024 * 1024) {
  die("❌ Face image is invalid or too large (max 2MB).");
}
$info = @getimagesizefromstring($raw);
if (!$info || $info['mime'] !== 'image/jpeg') {
  die("❌ Face image is not a valid JPEG.");
}

// ===== PERSON MUST EXIST AND HAVE NO FACE YET =====
// The ID number is the barcode now; the face lives in face_data (one row per person)
$check = $conn->prepare("
  SELECT p.id, fd.descriptor AS face_descriptor
  FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id
  WHERE p.id_number = ? LIMIT 1
");
$check->bind_param("s", $barcode);
$check->execute();
$found = $check->get_result()->fetch_assoc();
$check->close();

if (!$found) {
  die("❌ ID not found.");
}
if ($found['face_descriptor'] !== null && $found['face_descriptor'] !== '') {
  die("❌ A face is already registered for this ID.");
}
$personId = (int)$found['id'];

// ===== DUPLICATE FACE CHECK (against everyone else) =====
$q = $conn->prepare("
  SELECT fd.descriptor
  FROM face_data fd JOIN people p ON p.id = fd.person_id
  WHERE p.id_number <> ? AND fd.descriptor IS NOT NULL AND fd.descriptor <> ''
");
$q->bind_param("s", $barcode);
$q->execute();
$q->bind_result($storedJson);
while ($q->fetch()) {
  $stored = json_decode($storedJson, true);
  if (!is_array($stored) || count($stored) !== 128) continue;

  $sum = 0.0;
  for ($i = 0; $i < 128; $i++) {
    $diff = (float)$descriptor[$i] - (float)$stored[$i];
    $sum += $diff * $diff;
  }
  if (sqrt($sum) < FACE_MATCH_THRESHOLD) {
    $q->close();
    die("❌ This face is already registered under another ID.");
  }
}
$q->close();

// ===== SAVE FACE + CONSENT RECORD =====
$consentVersion = CONSENT_VERSION;

$exists = $conn->prepare("SELECT person_id FROM face_data WHERE person_id = ? LIMIT 1");
$exists->bind_param("i", $personId);
$exists->execute();
$hasRow = $exists->get_result()->num_rows > 0;
$exists->close();

if ($hasRow) {
  $stmt = $conn->prepare("
    UPDATE face_data
    SET descriptor = ?, image = ?, consent_at = NOW(), consent_version = ?
    WHERE person_id = ? AND (descriptor IS NULL OR descriptor = '')
  ");
  $stmt->bind_param("sssi", $descriptorJson, $face_image, $consentVersion, $personId);
} else {
  $stmt = $conn->prepare("
    INSERT INTO face_data (person_id, descriptor, image, consent_at, consent_version)
    VALUES (?, ?, ?, NOW(), ?)
  ");
  $stmt->bind_param("isss", $personId, $descriptorJson, $face_image, $consentVersion);
}

if ($stmt->execute() && $stmt->affected_rows === 1) {
  unset($_SESSION['liveness'], $_SESSION['scan_barcode'], $_SESSION['verified_at']);   // one-time use
  echo "✅ Face registered successfully!";
} else {
  echo "❌ Error: " . ($stmt->error ?: "nothing was saved.");
}
$stmt->close();
?>