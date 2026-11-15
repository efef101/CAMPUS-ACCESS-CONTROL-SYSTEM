<?php
session_start();
include 'db.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$authorized =
    !empty($_SESSION['security_logged_in']) ||
    !empty($_SESSION['admin_logged_in'])    ||
    !empty($_SESSION['officer_logged_in']);

// Release the session lock so polling never blocks other requests
session_write_close();

if (!$authorized) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized'
    ]);
    exit;
}

/*
 * NOTE: if your `logs` table has no `role` or `type` column, remove
 * them from this SELECT. The error message below will tell you.
 */
$result = $conn->query("
    SELECT id, name, role, status, type, timestamp
    FROM logs
    ORDER BY timestamp DESC
    LIMIT 20
");

if (!$result) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Query failed: ' . $conn->error
    ]);
    exit;
}

$logs = [];
while ($row = $result->fetch_assoc()) {
    $logs[] = $row;
}

echo json_encode([
    'success' => true,
    'logs'    => $logs
], JSON_UNESCAPED_UNICODE);