<?php
$conn = new mysqli("localhost", "root", "", "campus_system");
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
  
}

// Active Sessions tracking (keep this line LAST)
require_once __DIR__ . '/session_track.php';