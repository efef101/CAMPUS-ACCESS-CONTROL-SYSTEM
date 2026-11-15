<?php
session_start();
require_once 'db.php';

// Mark this administrator session as logged out (a tracking problem must never block the logout)
sess_end($conn, 'admin');

// Log out ONLY the administrator. Other roles stay logged in.
unset($_SESSION['admin_logged_in'], $_SESSION['admin_username']);

header("Location: login.php");
exit;