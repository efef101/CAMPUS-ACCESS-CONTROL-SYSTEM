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
| DECIDE WHICH ROLE THIS REQUEST IS FOR (?role=admin|officer|security)
|--------------------------------------------------------------------------
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
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
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
    echo json_encode(['success' => false, 'message' => $message]);
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
| Column aliases keep the names the dashboards already read
| (username, action, status, timestamp, name).
|--------------------------------------------------------------------------
*/

if ($requested === 'admin' || $requested === 'officer') {

    $totalUsers    = fetchCount($conn, "SELECT COUNT(*) AS c FROM people");
    $totalSecurity = fetchCount($conn, "SELECT COUNT(*) AS c FROM staff WHERE role <> 'admin'");
    $todayLogs     = fetchCount($conn, "SELECT COUNT(*) AS c FROM access_logs WHERE DATE(logged_at) = CURDATE()");

    $authenticationLogs = fetchRows($conn, "
        SELECT username_snapshot AS username, action, status, logged_at AS timestamp
        FROM auth_logs
        ORDER BY logged_at DESC, id DESC
        LIMIT 5
    ");

    $recentLogs = fetchRows($conn, "
        SELECT COALESCE(name_snapshot, id_number) AS name, event AS status, logged_at AS timestamp
        FROM access_logs
        ORDER BY logged_at DESC, id DESC
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
        FROM people
        WHERE status = 'IN'
    ");

    $visitorsInside = fetchRows($conn, "
        SELECT name, purpose
        FROM visitors
        WHERE status = 'IN'
    ");

    $recentLogs = fetchRows($conn, "
        SELECT COALESCE(name_snapshot, id_number) AS name, event AS status, logged_at AS timestamp
        FROM access_logs
        ORDER BY logged_at DESC, id DESC
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
echo json_encode(['success' => false, 'message' => 'Unable to determine user role']);
exit;