<?php
include 'db.php';

header('Content-Type: application/json');

$code = trim($_POST['code'] ?? '');

if ($code === '') {
  echo json_encode(['type' => 'unknown']);
  exit;
}

// Check visitors table first
$stmt = $conn->prepare("SELECT id FROM visitors WHERE qr_code = ?");
$stmt->bind_param("s", $code);
$stmt->execute();
if ($stmt->get_result()->num_rows > 0) {
  echo json_encode(['type' => 'visitor']);
  exit;
}

// Check registered users table
$stmt = $conn->prepare("SELECT id FROM users WHERE id_number = ?");
$stmt->bind_param("s", $code);
$stmt->execute();
if ($stmt->get_result()->num_rows > 0) {
  echo json_encode(['type' => 'user']);
  exit;
}

echo json_encode(['type' => 'unknown']);
