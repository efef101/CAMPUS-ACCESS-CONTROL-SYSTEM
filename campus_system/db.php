
<?php
$host = "sql211.infinityfree.com";
$username = "if0_43128475";
$password = "YOUR_VPANEL_PASSWORD";
$database = "if0_43128475_campusdb";

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    die("Database connection failed. Please try again later.");
}

$conn->set_charset("utf8mb4");
?>
