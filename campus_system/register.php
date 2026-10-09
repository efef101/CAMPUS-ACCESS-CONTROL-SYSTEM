<?php
include 'db.php';

// ===== GET JSON DATA =====
$data = json_decode(file_get_contents("php://input"), true);
if (!$data) {
  die("❌ Invalid data received.");
}

$id           = trim($data['id_number']        ?? '');
$fn           = trim($data['first_name']       ?? '');
$ln           = trim($data['last_name']        ?? '');
$role         = trim($data['role']             ?? '');
$course       = trim($data['course']           ?? '');
$dept_student = trim($data['department_student'] ?? '');
$dept_staff   = trim($data['department_staff'] ?? '');
$position     = trim($data['position']         ?? '');
$descriptorJson = $data['face_descriptor']     ?? '';
$face_image   = $data['face_image']            ?? '';   // base64 image

// ===== BASIC VALIDATION =====
if (!preg_match('/^[0-9]{1,8}$/', $id)) {
  die("❌ Invalid ID. Use 1–8 digits.");
}
if ($fn === '' || $ln === '' || $role === '') {
  die("❌ Missing required fields.");
}

// ===== ROLE LOGIC =====
if ($role === "student") {
  if ($course === '' || $dept_student === '') {
    die("❌ Please select both course and department.");
  }
  $department = $dept_student;
  $position   = null;
} else {
  if ($dept_staff === '' || $position === '') {
    die("❌ Faculty/Staff must have department and position.");
  }
  $course     = null;
  $department = $dept_staff;
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

if ($face_image === '') {
  die("❌ Face image missing.");
}

// ===== INSERT =====
$stmt = $conn->prepare("
  INSERT INTO users 
  (id_number, first_name, last_name, role, course, department, position, barcode, face_descriptor, face_image, status)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OUT')
");

$stmt->bind_param(
  "ssssssssss",
  $id, $fn, $ln, $role,
  $course, $department, $position,
  $id,
  $descriptorJson,
  $face_image
);

if ($stmt->execute()) {
  echo "✅ Registered successfully!";
} else {
  echo "❌ Error: " . $stmt->error;
}
?>