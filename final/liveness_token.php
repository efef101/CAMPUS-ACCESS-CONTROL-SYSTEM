<?php
// Issues a short-lived, one-time token after the browser reports a passed liveness check.
session_start();
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  echo json_encode(['error' => 'Method not allowed']);
  exit;
}

// ===== SIMPLE RATE LIMIT (max 10 tokens per minute per session) =====
$now = time();
$_SESSION['token_requests'] = array_filter(
  $_SESSION['token_requests'] ?? [],
  fn($t) => $t > $now - 60
);
if (count($_SESSION['token_requests']) >= 10) {
  http_response_code(429);
  echo json_encode(['error' => 'Too many attempts. Wait a minute.']);
  exit;
}
$_SESSION['token_requests'][] = $now;

// ===== VALIDATE PROOF SENT BY THE BROWSER =====
$data = json_decode(file_get_contents('php://input'), true);
$allowed    = ['blink', 'left', 'right', 'mouth'];
$challenges = $data['challenges'] ?? [];
$sharpness  = $data['sharpness'] ?? null;

if (
  !is_array($challenges) ||
  count($challenges) < 2 ||
  count($challenges) !== count(array_unique($challenges)) ||
  array_diff($challenges, $allowed)
) {
  http_response_code(400);
  echo json_encode(['error' => 'Invalid liveness proof']);
  exit;
}

if (!is_numeric($sharpness) || $sharpness < 0) {
  http_response_code(400);
  echo json_encode(['error' => 'Invalid liveness proof']);
  exit;
}

// ===== ISSUE TOKEN =====
$token = bin2hex(random_bytes(16));
$_SESSION['liveness'] = [
  'token'      => $token,
  'issued_at'  => $now,
  'challenges' => array_values($challenges),
  'sharpness'  => (float)$sharpness,
];

echo json_encode(['token' => $token]);