<?php
session_start();
include 'db.php';

// Version of the privacy notice shown on the registration page.
// Change this string whenever the notice wording changes, and update the same value in the page's JavaScript.
define('CONSENT_VERSION', '2026-10-v1');

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

// ===== BARCODE MUST MATCH THE ONE VERIFIED IN THIS SESSION =====
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

// ===== RECORD MUST EXIST AND HAVE NO FACE YET =====
$check = $conn->prepare("SELECT face_descriptor FROM users WHERE barcode = ? LIMIT 1");
$check->bind_param("s", $barcode);
$check->execute();
$check->bind_result($existingFace);
if (!$check->fetch()) {
  $check->close();
  die("❌ ID not found.");
}
$check->close();
if ($existingFace !== null && $existingFace !== '') {
  die("❌ A face is already registered for this ID.");
}

// ===== DUPLICATE FACE CHECK (against everyone else) =====
define('FACE_MATCH_THRESHOLD', 0.5);

$q = $conn->prepare("SELECT face_descriptor FROM users WHERE barcode <> ? AND face_descriptor IS NOT NULL AND face_descriptor <> ''");
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

// ===== SAVE FACE + CONSENT RECORD ON THE EXISTING RECORD =====
$consentVersion = CONSENT_VERSION;
$stmt = $conn->prepare("
  UPDATE users
  SET face_descriptor = ?, face_image = ?, consent_at = NOW(), consent_version = ?
  WHERE barcode = ? AND (face_descriptor IS NULL OR face_descriptor = '')
");
$stmt->bind_param("ssss", $descriptorJson, $face_image, $consentVersion, $barcode);

if ($stmt->execute() && $stmt->affected_rows === 1) {
  unset($_SESSION['liveness'], $_SESSION['scan_barcode'], $_SESSION['verified_at']);   // one-time use
  echo "✅ Face registered successfully!";
} else {
  echo "❌ Error: " . ($stmt->error ?: "nothing was saved.");
}
$stmt->close();
?>