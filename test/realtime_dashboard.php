<?php
session_start();
require_once 'db.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

/*
|--------------------------------------------------------------------------
| READ SESSION FLAGS, THEN RELEASE THE SESSION LOCK
|--------------------------------------------------------------------------
*/

$hasAdmin    = !empty($_SESSION['admin_logged_in']);
$hasOfficer  = !empty($_SESSION['officer_logged_in']);
$hasSecurity = !empty($_SESSION['security_logged_in']);

session_write_close();

/*
|--------------------------------------------------------------------------
| DECIDE WHICH ROLE THIS REQUEST IS FOR
|--------------------------------------------------------------------------
| The page tells us which role it wants (?role=admin|officer|security).
| If it asks for a role the session doesn't have, we return 401 instead of
| silently answering with a different role (which made the page show OFFLINE).
| If no role is given, fall back to the first role the session has.
*/

$requested = $_GET['role'] ?? '';

if ($requested === '') {
    if     ($hasAdmin)    $requested = 'admin';
    elseif ($hasOfficer)  $requested = 'officer';
    elseif ($hasSecurity) $requested = 'security';
}

$allowed = [
    'admin'    => $hasAdmin,
    'officer'  => $hasOfficer,
    'security' => $hasSecurity,
];

if (!isset($allowed[$requested]) || !$allowed[$requested]) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized'
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

function fail($message)
{
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => $message
    ]);
    exit;
}

function fetchRows($conn, $sql)
{
    $result = $conn->query($sql);

    if (!$result) {
        fail('Query failed: ' . $conn->error);
    }

    $rows = [];
    while ($row = $result->fetch_assoc()) {
        $rows[] = $row;
    }
    return $rows;
}

function fetchCount($conn, $sql)
{
    $result = $conn->query($sql);

    if (!$result) {
        fail('Query failed: ' . $conn->error);
    }

    $row = $result->fetch_assoc();
    return (int)$row['c'];
}

/*
|--------------------------------------------------------------------------
| ADMIN + OFFICER (same data shape)
|--------------------------------------------------------------------------
*/

if ($requested === 'admin' || $requested === 'officer') {

    $totalUsers    = fetchCount($conn, "SELECT COUNT(*) AS c FROM users");
    $totalSecurity = fetchCount($conn, "SELECT COUNT(*) AS c FROM security");
    $todayLogs     = fetchCount($conn, "SELECT COUNT(*) AS c FROM logs WHERE DATE(timestamp) = CURDATE()");

    $authenticationLogs = fetchRows($conn, "
        SELECT username, action, status, timestamp
        FROM authentication_logs
        ORDER BY timestamp DESC
        LIMIT 5
    ");

    $recentLogs = fetchRows($conn, "
        SELECT name, status, timestamp
        FROM logs
        ORDER BY timestamp DESC
        LIMIT 5
    ");

    echo json_encode([
        'success' => true,
        'role'    => $requested,
        'stats'   => [
            'totalUsers'    => $totalUsers,
            'totalSecurity' => $totalSecurity,
            'todayLogs'     => $todayLogs
        ],
        'authenticationLogs' => $authenticationLogs,
        'recentLogs'         => $recentLogs,
        'server_time'        => date('Y-m-d H:i:s')
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

/*
|--------------------------------------------------------------------------
| SECURITY
|--------------------------------------------------------------------------
*/

if ($requested === 'security') {

    $usersInside = fetchRows($conn, "
        SELECT CONCAT(first_name, ' ', last_name) AS name, role
        FROM users
        WHERE status = 'IN'
    ");

    $visitorsInside = fetchRows($conn, "
        SELECT name, purpose
        FROM visitors
        WHERE status = 'IN'
    ");

    $recentLogs = fetchRows($conn, "
        SELECT name, status, timestamp
        FROM logs
        ORDER BY timestamp DESC
        LIMIT 10
    ");

    echo json_encode([
        'success' => true,
        'role'    => 'security',
        'stats'   => [
            'usersInside'    => count($usersInside),
            'visitorsInside' => count($visitorsInside),
            'recentLogs'     => count($recentLogs)
        ],
        'usersInside'    => $usersInside,
        'visitorsInside' => $visitorsInside,
        'recentLogs'     => $recentLogs,
        'server_time'    => date('Y-m-d H:i:s')
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

http_response_code(400);
echo json_encode([
    'success' => false,
    'message' => 'Unable to determine user role'
]);
exit;