<?php
include 'db.php';

$code = $_POST['barcode'] ?? $_GET['code'] ?? '';

if (!$code) {
    echo "❌ No code provided";
    exit;
}

// ================= USERS =================
$stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
$stmt->bind_param("s", $code);
$stmt->execute();
$user_result = $stmt->get_result();

if ($user_result->num_rows > 0) {

    $user = $user_result->fetch_assoc();

    $name = $user['first_name'] . " " . $user['last_name'];
    $role = $user['role'];

    // ENTRY
    if ($user['status'] == 'OUT') {

        $conn->query("UPDATE users SET status='IN' WHERE id_number='$code'");

        $status = "IN";
        $type = "ENTRY";

        $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
        $log->bind_param("sssss", $code, $name, $role, $status, $type);
        $log->execute();

        echo "✅ ENTRY GRANTED<br>$name entered campus";
        exit;
    }

    // EXIT
    if ($user['status'] == 'IN') {

        $conn->query("UPDATE users SET status='OUT' WHERE id_number='$code'");

        $status = "IN";
        $type = "EXIT";

        $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
        $log->bind_param("sssss", $code, $name, $role, $status, $type);
        $log->execute();

        echo "🚪 EXIT RECORDED<br>$name left campus";
        exit;
    }
}

// ================= VISITORS =================
$stmt = $conn->prepare("SELECT * FROM visitors WHERE qr_code = ?");
$stmt->bind_param("s", $code);
$stmt->execute();
$visitor_result = $stmt->get_result();

if ($visitor_result->num_rows > 0) {

    $visitor = $visitor_result->fetch_assoc();
    $name = $visitor['name'];
    $role = "visitor";

    // EXPIRED
    if (strtotime($visitor['expires_at']) < time()) {

        $status = "DENIED";
        $type = "ENTRY";

        $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
        $log->bind_param("sssss", $code, $name, $role, $status, $type);
        $log->execute();

        echo "❌ QR EXPIRED";
        exit;
    }

    // ENTRY
    if ($visitor['status'] == 'OUT') {

        $conn->query("UPDATE visitors SET status='IN', is_used=1 WHERE qr_code='$code'");

        $status = "IN";
        $type = "ENTRY";

        $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
        $log->bind_param("sssss", $code, $name, $role, $status, $type);
        $log->execute();

        echo "✅ ENTRY IN <br>$name entered campus";
        exit;
    }

    // EXIT
    if ($visitor['status'] == 'IN') {

        $conn->query("UPDATE visitors SET status='OUT' WHERE qr_code='$code'");

        $status = "IN";
        $type = "EXIT";

        $log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
        $log->bind_param("sssss", $code, $name, $role, $status, $type);
        $log->execute();

        echo "🚪 EXIT RECORDED<br>$name left campus";
        exit;
    }
}

// ================= INVALID =================
$name = $code;
$role = "unknown";
$status = "DENIED";
$type = "ENTRY";

$log = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type) VALUES (?, ?, ?, ?, ?)");
$log->bind_param("sssss", $code, $name, $role, $status, $type);
$log->execute();

echo "❌ ACCESS DENIED";
?>