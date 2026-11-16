<?php
session_start();
include 'db.php';
include_once 'auth.php';

// Live feed for the Access Logs page (polled every 3 seconds).
// Written for campus_system_v2 from the fields that page reads, so replace the old realtime_logs.php with this.
if (auth_role() === null) {
  http_response_code(401);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['success' => false, 'message' => 'Session expired']);
  exit;
}

session_write_close();   // read-only request: don't hold the session lock
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store, must-revalidate');

$logs = [];
$r = $conn->query("
  SELECT a.id, a.id_number, a.name_snapshot AS name, COALESCE(a.person_type, '') AS role,
         CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status,
         a.event AS type, a.reason, a.flagged, a.logged_at AS timestamp
  FROM access_logs a
  ORDER BY a.logged_at DESC, a.id DESC
  LIMIT 50
");
while ($r && $row = $r->fetch_assoc()) {
  $logs[] = $row;
}

echo json_encode(['success' => true, 'logs' => $logs], JSON_UNESCAPED_UNICODE);