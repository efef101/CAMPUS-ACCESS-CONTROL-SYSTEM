<?php
session_start();
require_once 'db.php';

// Record the logout (a logging problem must never block the logout)
$username = $_SESSION['admin_username'] ?? '';
$staffId  = (int)($_SESSION['staff_ids']['admin'] ?? 0) ?: null;
if ($username !== '') {
  try {
    $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
    $q = $conn->prepare("INSERT INTO auth_logs (staff_id, username_snapshot, action, status, ip_address) VALUES (?, ?, 'LOGOUT', 'SUCCESS', ?)");
    $q->bind_param("iss", $staffId, $username, $ip);
    $q->execute();
    $q->close();
  } catch (Throwable $e) {
    error_log("admin logout log error: " . $e->getMessage());
  }
}

// Mark this administrator session as logged out in Active Sessions
sess_end($conn, 'admin');

// Log out ONLY the administrator. Other roles stay logged in.
unset($_SESSION['admin_logged_in'], $_SESSION['admin_username'], $_SESSION['staff_ids']['admin']);

header("Location: login.php");
exit;