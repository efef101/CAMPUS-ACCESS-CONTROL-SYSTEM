<?php
include 'db.php';

header('Content-Type: application/json');

$code = $_GET['code'] ?? '';
if (!$code) {
    echo json_encode(['error' => 'Missing code parameter']);
    exit;
}

$stmt = $conn->prepare("SELECT first_name, last_name, face_descriptor FROM users WHERE id_number = ?");
if (!$stmt) {
    echo json_encode(['error' => 'Database prepare failed']);
    exit;
}

$stmt->bind_param('s', $code);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo json_encode(['error' => 'User not found']);
    exit;
}

$user = $result->fetch_assoc();
$descriptor = json_decode($user['face_descriptor'], true);

if (!is_array($descriptor) || count($descriptor) === 0) {
    echo json_encode(['error' => 'No valid stored face descriptor for this user']);
    exit;
}

echo json_encode([
    'descriptor' => $descriptor,
    'first_name' => $user['first_name'],
    'last_name' => $user['last_name'],
]);
