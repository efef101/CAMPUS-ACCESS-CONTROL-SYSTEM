<?php
// Live feed for the Officer and Admin dashboards (the Security dashboard has its own ?realtime).
session_start();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

if (!isset($_SESSION['admin_logged_in']) && !isset($_SESSION['officer_logged_in']) && !isset($_SESSION['security_logged_in'])) {
  http_response_code(401);
  echo json_encode(['success' => false, 'message' => 'Session expired']);
  exit;
}
session_write_close();   // read-only request: don't hold the session lock

include 'db.php';
require_once __DIR__ . '/dashboard_flags.php';

$limit = max(1, min(20, (int)($_GET['limit'] ?? 5)));

try {
  echo json_encode([
    'success'     => true,
    'logsHtml'    => dash_logs_rows($conn, $limit),
    'flaggedHtml' => dash_flagged_rows($conn, 5),
  ], JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
  error_log('flagged_feed failed: ' . $e->getMessage());
  http_response_code(500);
  echo json_encode(['success' => false, 'message' => 'Feed error']);
}