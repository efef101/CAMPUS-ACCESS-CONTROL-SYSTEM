<?php
// Database connection. Points at the NEW normalized database.
$conn = new mysqli("localhost", "root", "", "campus_system_v2");
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}
$conn->set_charset("utf8mb4");

// Active Sessions tracking (keep this line LAST)
require_once __DIR__ . '/session_track.php';