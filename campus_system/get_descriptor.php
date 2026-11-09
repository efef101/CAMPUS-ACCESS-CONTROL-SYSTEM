<?php
include 'db.php';

$id = $_GET['id_number'] ?? '';
if (!preg_match('/^[0-9]{1,8}$/', $id)) {
  echo json_encode(['success' => false, 'message' => 'Invalid ID.']);
  exit;
}

$stmt = $conn->prepare("SELECT first_name, last_name, face_descriptor FROM users WHERE id_number = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
$result = $stmt->get_result();
if ($result->num_rows === 0) {
  echo json_encode(['success' => false, 'message' => 'User not found.']);
  exit;
}

$user = $result->fetch_assoc();
if (empty($user['face_descriptor'])) {
  echo json_encode(['success' => false, 'message' => 'Face descriptor not registered.']);
  exit;
}

$descriptor = json_decode($user['face_descriptor'], true);
if (!is_array($descriptor)) {
  echo json_encode(['success' => false, 'message' => 'Invalid face descriptor.']);
  exit;
}

echo json_encode(['success' => true, 'name' => $user['first_name'] . ' ' . $user['last_name'], 'descriptor' => $descriptor]);
?>