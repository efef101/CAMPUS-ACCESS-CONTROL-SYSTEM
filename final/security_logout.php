<?php
session_start();
include 'db.php';

// Read the name BEFORE removing it from the session
$username = $_SESSION['security_username'] ?? $_SESSION['username'] ?? '';
$staffId  = (int)($_SESSION['staff_ids']['personnel'] ?? 0) ?: null;

// Record the logout (a logging problem must never block the logout)
if ($username !== '') {
  try {
    $username = substr((string)$username, 0, 100);
    $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
    $q = $conn->prepare("INSERT INTO auth_logs (staff_id, username_snapshot, action, status, ip_address) VALUES (?, ?, 'LOGOUT', 'SUCCESS', ?)");
    $q->bind_param("iss", $staffId, $username, $ip);
    $q->execute();
    $q->close();
  } catch (Throwable $e) {
    error_log("security logout log error: " . $e->getMessage());
  }
}

// Mark this personnel session as logged out in Active Sessions
sess_end($conn, 'security');

// Log out ONLY the security personnel. Other roles stay logged in.
unset($_SESSION['security_logged_in'], $_SESSION['security_username'], $_SESSION['staff_ids']['personnel']);

// Remove the shared username only if no other security role is using it
if (empty($_SESSION['officer_logged_in'])) {
  unset($_SESSION['username']);
}

header("Location: login.php");
exit;