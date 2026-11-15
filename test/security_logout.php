<?php
session_start();
include 'db.php';

// Read the name BEFORE removing it from the session
$username = $_SESSION['security_username'] ?? $_SESSION['username'] ?? '';

// Record the logout (a logging problem must never block the logout)
if ($username !== '') {
    try {
        $username = substr((string)$username, 0, 100);
        $action   = 'LOGOUT';
        $status   = 'SUCCESS';

        $q = $conn->prepare("INSERT INTO authentication_logs (username, action, status, timestamp) VALUES (?, ?, ?, NOW())");
        if ($q) {
            $q->bind_param("sss", $username, $action, $status);
            $q->execute();
            $q->close();
        } else {
            error_log("security logout log prepare failed: " . $conn->error);
        }
    } catch (Throwable $e) {
        error_log("security logout log error: " . $e->getMessage());
    }
}

// Mark this personnel session as logged out in Active Sessions
sess_end($conn, 'security');

// Log out ONLY the security personnel. Other roles stay logged in.
unset($_SESSION['security_logged_in'], $_SESSION['security_username']);

// Remove the shared username only if no other security role is using it
if (empty($_SESSION['officer_logged_in'])) {
    unset($_SESSION['username']);
}

header("Location: login.php");
exit;