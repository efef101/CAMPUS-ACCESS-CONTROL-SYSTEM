<?php
session_start();
include 'db.php';
include_once 'auth.php';

// Only logged-in security personnel can open this page or register visitors
require_auth($conn, ['personnel']);

header("Cache-Control: no-cache, no-store, must-revalidate");

// CSRF token
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$success = '';
$error = '';

const MAX_GROUP_SIZE = 50;

// Values kept in the form after an error (cleared after a success)
$old = [
  'visitor_type' => 'INDIVIDUAL',
  'qr_code'      => '',
  'name'         => '',
  'purpose'      => '',
  'destination'  => '',
  'group_name'   => '',
  'group_size'   => '',
  'members'      => [],
];

// True when this QR code belongs to a visitor who is still inside
function qr_in_use($conn, $qr) {
  $s = $conn->prepare("SELECT status FROM visitors WHERE qr_code = ?");
  $s->bind_param("s", $qr);
  $s->execute();
  $row = $s->get_result()->fetch_assoc();
  $s->close();
  return $row && $row['status'] === 'IN';
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
    $error = "Invalid request. Please try again.";
  } else {

    $qr_code       = trim($_POST['qr_code'] ?? '');
    $name          = trim($_POST['name'] ?? '');
    $purpose       = trim($_POST['purpose'] ?? '');
    $destination   = trim($_POST['destination'] ?? '');
    $visitor_type  = (($_POST['visitor_type'] ?? '') === 'GROUP') ? 'GROUP' : 'INDIVIDUAL';
    $group_name    = trim($_POST['group_name'] ?? '');
    $group_size_in = trim((string)($_POST['group_size'] ?? ''));

    // member names typed in the generated fields
    $members_in = $_POST['members'] ?? [];
    if (!is_array($members_in)) { $members_in = []; }
    $members = [];
    foreach ($members_in as $m) {
      $members[] = substr(trim((string)$m), 0, 100);
    }

    // remember what was typed in case there is an error
    $old = [
      'visitor_type' => $visitor_type,
      'qr_code'      => $qr_code,
      'name'         => $name,
      'purpose'      => $purpose,
      'destination'  => $destination,
      'group_name'   => $group_name,
      'group_size'   => $group_size_in,
      'members'      => $members,
    ];

    $group_size = 1;
    if ($visitor_type === 'GROUP' && ctype_digit($group_size_in)) {
      $group_size = (int)$group_size_in;
    }

    if (!$qr_code || !$name || !$purpose || !$destination) {
      $error = "All fields are required.";

    } elseif ($visitor_type === 'GROUP' && $group_name === '') {
      $error = "Please enter the group or organization name.";

    } elseif ($visitor_type === 'GROUP' && ($group_size < 2 || $group_size > MAX_GROUP_SIZE)) {
      $error = "Number of visitors in a group must be between 2 and " . MAX_GROUP_SIZE . ".";

    } elseif ($visitor_type === 'GROUP' && count($members) !== $group_size - 1) {
      $error = "Please enter the name of every group member.";

    } elseif ($visitor_type === 'GROUP' && in_array('', $members, true)) {
      $error = "Please enter the name of every group member.";

    } elseif (qr_in_use($conn, $qr_code)) {
      $error = "This QR code is still in use. The visitor is inside, so scan it to exit first.";

    } else {

      if ($visitor_type === 'GROUP') {
        $group_name = substr($group_name, 0, 150);
      } else {
        $group_size = 1;
        $group_name = null;
        $members    = [];
      }

      $conn->begin_transaction();

      try {
        // If this QR code was registered before, update that visitor instead of deleting it.
        // Deleting would break the entry/exit history linked to that visitor.
        $find = $conn->prepare("SELECT id FROM visitors WHERE qr_code = ?");
        $find->bind_param("s", $qr_code);
        $find->execute();
        $existing = $find->get_result()->fetch_assoc();
        $find->close();

        if ($existing) {
          $visitorId = (int)$existing['id'];
          // used_at is cleared so the QR code can be scanned again after registering
          $stmt = $conn->prepare("UPDATE visitors SET name = ?, purpose = ?, destination = ?, visitor_type = ?, group_name = ?, group_size = ?, expires_at = NULL, used_at = NULL WHERE id = ?");
          $stmt->bind_param("sssssii", $name, $purpose, $destination, $visitor_type, $group_name, $group_size, $visitorId);
          if (!$stmt->execute()) { throw new RuntimeException($stmt->error); }
          $stmt->close();
        } else {
          $stmt = $conn->prepare("INSERT INTO visitors (qr_code, name, purpose, destination, visitor_type, group_name, group_size) VALUES (?, ?, ?, ?, ?, ?, ?)");
          $stmt->bind_param("ssssssi", $qr_code, $name, $purpose, $destination, $visitor_type, $group_name, $group_size);
          if (!$stmt->execute()) { throw new RuntimeException($stmt->error); }
          $visitorId = (int)$stmt->insert_id;
          $stmt->close();
        }

        // Replace the member list for this visitor
        $del = $conn->prepare("DELETE FROM visitor_group_members WHERE visitor_id = ?");
        $del->bind_param("i", $visitorId);
        if (!$del->execute()) { throw new RuntimeException($del->error); }
        $del->close();

        if ($visitor_type === 'GROUP') {
          $ins = $conn->prepare("INSERT INTO visitor_group_members (visitor_id, member_name) VALUES (?, ?)");
          foreach ($members as $memberName) {
            $ins->bind_param("is", $visitorId, $memberName);
            if (!$ins->execute()) { throw new RuntimeException($ins->error); }
          }
          $ins->close();
        }

        $conn->commit();

        $success = ($visitor_type === 'GROUP')
          ? "Group registered successfully ($group_size visitors)."
          : "Visitor registered successfully.";

        // clear the form after success
        $old = [
          'visitor_type' => 'INDIVIDUAL',
          'qr_code' => '', 'name' => '', 'purpose' => '',
          'destination' => '', 'group_name' => '', 'group_size' => '',
          'members' => [],
        ];

      } catch (Throwable $e) {
        $conn->rollback();
        error_log("Visitor register failed: " . $e->getMessage());
        $error = "Could not register the visitor. Please try again.";
      }
    }
  }
}

$isGroup = ($old['visitor_type'] === 'GROUP');

// Inline SVG icons (same set as the dashboards)
function icon($name) {
  $paths = [
    'home'    => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'scan'    => '<path d="M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3"/><path d="M4 12h16"/>',
    'list'    => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'mega' => '<path d="M3 11v2a1 1 0 001 1h2l7 4V6L6 10H4a1 1 0 00-1 1z"/><path d="M16 9a4 4 0 010 6M19 7a7 7 0 010 10"/>',
    'visitor' => '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6 16c.5-1.5 1.7-2 3-2s2.5.5 3 2M15 10h3M15 13h3"/>',
    'add'     => '<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6.5 7-6.5M18 14v6M15 17h6"/>',
    'logout'  => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    'check'   => '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/>',
    'alert'   => '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5h.01"/>',
    'person'  => '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 016-6h4a6 6 0 016 6v1"/>',
    'group'   => '<circle cx="9" cy="8" r="3.5"/><path d="M2 20v-1a5 5 0 015-5h4a5 5 0 015 5v1"/><path d="M16 4.6a3.5 3.5 0 010 6.8M18 14.2a5 5 0 014 4.8v1"/>',
  ];
  return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register Visitor</title>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --ink: #16233d;
  --navy: #1c3a5e;
  --line: #dce4ef;
  --muted: #8a9bb5;
  --gold: #f0b429;
  --gold-soft: #fffdf5;
  --gold-glow: 0 8px 24px rgba(240,180,41,0.25);
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #fafbfd;
  min-height: 100vh;
  display: flex;
  color: var(--ink);
}

svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }

/* SIDEBAR */
.sidebar {
  width: 220px;
  flex-shrink: 0;
  background: linear-gradient(180deg, #1c3a5e, #0f2440);
  border-right: 1px solid #0f2440;
  height: 100vh;
  position: sticky;
  top: 0;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  padding: 24px 18px;
  gap: 12px;
}

.sidebar .logo {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  text-align: center;
}

/* school + campus name under the logo */
.sidebar .logo-text { display: flex; flex-direction: column; gap: 2px; }
.sidebar .logo-univ { font-size: 12px; font-weight: 700; line-height: 1.3; color: #fff; }
.sidebar .logo-campus { font-size: 11px; font-weight: 500; color: rgba(255,255,255,0.6); }

.sidebar .logo img {
  width: 44px; height: 44px; border-radius: 12px; object-fit: cover;
}

.sidebar-divider { width: 100%; height: 1px; background: rgba(255,255,255,0.12); margin: 4px 0; }

/* the row: [icon box] name */
.sidebar .nav-item {
  display: flex; align-items: center; gap: 14px;
  width: 100%;
  color: #fff; text-decoration: none;
  font-size: 14px; font-weight: 500; white-space: nowrap;
  position: relative;
}

/* the icon box */
.sidebar .nav-icon {
  width: 44px; height: 44px; border-radius: 12px; flex-shrink: 0;
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.12);
  display: flex; align-items: center; justify-content: center;
  transition: background .2s, border-color .2s, transform .2s;
}
.sidebar .nav-icon svg { width: 20px; height: 20px; }

.sidebar .nav-label { color: rgba(255,255,255,0.85); overflow: hidden; text-overflow: ellipsis; }

.sidebar .nav-item:hover .nav-icon {
  background: rgba(240,180,41,0.18);
  border-color: var(--gold);
  transform: translateY(-1px);
}
.sidebar .nav-item.active .nav-icon {
  background: rgba(240,180,41,0.25);
  border-color: var(--gold);
}
.sidebar .nav-item.active .nav-label { color: #fff; font-weight: 600; }
.sidebar .nav-item:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; border-radius: 12px; }
.sidebar .logout-item { margin-top: auto; }

/* MAIN */
.main { flex: 1; min-width: 0; padding: 32px; }

/* HEADER */
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }

.btn {
  display: inline-block;
  text-decoration: none;
  border-radius: 12px;
  border: 1px solid var(--line);
  background: #fff;
  color: var(--ink);
  font-family: inherit;
  font-size: 13px; font-weight: 600;
  cursor: pointer;
  transition: transform .15s, background .15s, border-color .15s, box-shadow .15s;
}
.btn { padding: 11px 24px; }

.btn:hover {
  transform: translateY(-2px);
  background: var(--gold-soft);
  border-color: var(--gold);
  box-shadow: var(--gold-glow);
}
.btn:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }

.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }

/* FORM CARD */
.form-card {
  background: #fff;
  border-radius: 14px;
  border: 1px solid var(--line);
  box-shadow: 0 1px 3px rgba(22,58,94,0.05);
  padding: 28px;
  width: 100%;
  max-width: 520px;
  margin: 0 auto;
  transition: border-color .2s, box-shadow .2s;
}
.form-card:hover { border-color: var(--gold); box-shadow: var(--gold-glow); }

.form-card h3 {
  font-size: 14px; font-weight: 600; margin-bottom: 20px;
  display: flex; align-items: center; gap: 12px;
}
.form-card h3 .icon {
  width: 36px; height: 36px; flex-shrink: 0;
  border-radius: 12px; border: 2px dashed #c7d7ec; background: #f4f7fb;
  display: flex; align-items: center; justify-content: center; color: var(--navy);
}
.form-card h3 .icon svg { width: 18px; height: 18px; }

/* FORM FIELDS */
.form-group { margin-bottom: 16px; }

.form-group label,
.type-label {
  display: block;
  font-size: 11px; font-weight: 600; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.06em;
  margin-bottom: 6px;
}

.form-group input {
  width: 100%;
  padding: 10px 14px;
  background: #f8fafc;
  border: 1px solid var(--line);
  border-radius: 10px;
  color: var(--ink);
  font-size: 13px;
  font-family: inherit;
  outline: none;
  transition: border-color .2s, background .2s, box-shadow .2s;
}
.form-group input::placeholder { color: #a3b3cc; }
.form-group input:focus {
  border-color: var(--gold);
  background: #fff;
  box-shadow: 0 0 0 3px rgba(240,180,41,0.18);
}

.hint {
  font-size: 11px;
  color: var(--muted);
  margin-top: 6px;
}

.form-actions { margin-top: 8px; }

/* VISITOR TYPE CHOICE (Individual / Group) */
.type-group { margin-bottom: 20px; border: none; }

.type-options {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}

.type-option { position: relative; display: block; cursor: pointer; }

/* the real radio stays in the page for keyboards and screen readers */
.type-option input {
  position: absolute;
  opacity: 0;
  inset: 0;
  width: 100%;
  height: 100%;
  margin: 0;
  cursor: pointer;
}

.type-box {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 14px;
  background: #f8fafc;
  border: 1px solid var(--line);
  border-radius: 12px;
  transition: border-color .2s, background .2s, box-shadow .2s;
}

.type-box .type-icon {
  width: 36px; height: 36px; flex-shrink: 0;
  border-radius: 10px;
  background: #eef3fa;
  border: 1px solid #c7d7ec;
  color: var(--navy);
  display: flex; align-items: center; justify-content: center;
  transition: background .2s, border-color .2s;
}
.type-box .type-icon svg { width: 18px; height: 18px; }

.type-box strong { display: block; font-size: 13px; font-weight: 600; color: var(--ink); }
.type-box small  { display: block; font-size: 11px; color: var(--muted); margin-top: 1px; }

.type-option:hover .type-box { border-color: var(--gold); }

.type-option input:checked + .type-box {
  background: var(--gold-soft);
  border-color: var(--gold);
  box-shadow: 0 0 0 3px rgba(240,180,41,0.18);
}
.type-option input:checked + .type-box .type-icon {
  background: rgba(240,180,41,0.25);
  border-color: var(--gold);
}

.type-option input:focus-visible + .type-box {
  outline: 2px solid var(--gold);
  outline-offset: 2px;
}

/* GROUP-ONLY SECTIONS */
.group-fields,
.members-box { display: none; }

.is-group .group-fields { display: block; }
.is-group .members-box.has-members { display: block; }

.group-fields,
.members-box {
  padding: 16px 16px 2px;
  background: var(--gold-soft);
  border: 1px solid #f3e3b0;
  border-radius: 12px;
  margin-bottom: 16px;
}

.group-fields .form-group input,
.members-box .form-group input { background: #fff; }

.members-title {
  font-size: 12px; font-weight: 600; color: var(--ink);
  margin-bottom: 14px;
}
.members-title span { color: var(--muted); font-weight: 500; }

/* ALERTS */
.alert {
  padding: 12px 16px;
  border-radius: 12px;
  font-size: 13px;
  margin: 0 auto 20px;
  max-width: 520px;
  display: flex; align-items: center; gap: 10px;
  max-height: 100px;
  overflow: hidden;
  transition: opacity .4s ease, transform .4s ease, max-height .4s ease,
              padding .4s ease, margin .4s ease, border-width .4s ease;
}
.alert svg { width: 18px; height: 18px; flex-shrink: 0; }
.alert-success { background: #e8f8ef; border: 1px solid #bdeccf; color: #16a34a; }
.alert-error   { background: #fdeaea; border: 1px solid #f6c6c6; color: #dc2626; }

/* Fade-out state (added by JS after 5 seconds) */
.alert.hide {
  opacity: 0;
  transform: translateY(-6px);
  max-height: 0;
  padding-top: 0;
  padding-bottom: 0;
  margin-bottom: 0;
  border-width: 0;
}

/* RESPONSIVE */
@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .sidebar .logo-text { display: none; }
  .sidebar .logo img { width: 40px; height: 40px; }

  /* Tooltip (names are hidden at this size) */
  .nav-item::after {
    content: attr(data-tip);
    position: absolute; left: 54px;
    background: var(--ink); color: #fff;
    font-size: 11px; padding: 4px 10px; border-radius: 6px; white-space: nowrap;
    border: 1px solid rgba(255,255,255,0.1);
    opacity: 0; pointer-events: none; transition: opacity .15s; z-index: 100;
  }
  .nav-item:hover::after, .nav-item:focus-visible::after { opacity: 1; }
  .main { padding: 20px; }
}

@media (max-width: 480px) {
  .type-options { grid-template-columns: 1fr; }
}

@media (prefers-reduced-motion: reduce) {
  .btn, .form-card, .sidebar .nav-icon, .alert,
  .type-box, .type-box .type-icon { transition: none; }
}
</style>

</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar" aria-label="Main">
  <div class="logo">
    <img src="lego.png" alt="Lego">
    <div class="logo-text">
      <span class="logo-univ">Cebu Technological University</span>
      <span class="logo-campus">Main Campus</span>
    </div>
  </div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="dashboard.php" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="security_logs.php" data-tip="AccessLogs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item active" href="visitor_register.php" data-tip="Register Visitor" aria-label="Register Visitor" aria-current="page"><span class="nav-icon"><?= icon('visitor') ?></span><span class="nav-label">Register Visitor</span></a>
  <a class="nav-item" href="announcements.php" data-tip="Announcements" aria-label="Announcements"><span class="nav-icon"><?= icon('mega') ?></span><span class="nav-label">Announcements</span></a>
  <a class="nav-item logout-item" href="security_logout.php" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<!-- MAIN -->
<main class="main">

  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <h1>Register Visitor</h1>
      <p><?= date('l, F j, Y') ?></p>
    </div>
  </div>

  <!-- ALERTS -->
  <?php if ($success): ?>
    <div class="alert alert-success" role="status"><?= icon('check') ?> <?= htmlspecialchars($success) ?></div>
  <?php endif; ?>
  <?php if ($error): ?>
    <div class="alert alert-error" role="alert"><?= icon('alert') ?> <?= htmlspecialchars($error) ?></div>
  <?php endif; ?>

  <!-- FORM -->
  <div class="form-card">
    <h3><span class="icon"><?= icon('visitor') ?></span> Visitor Details</h3>
    <form method="POST" id="visitorForm" class="<?= $isGroup ? 'is-group' : '' ?>">

      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">

      <!-- VISITOR TYPE -->
      <fieldset class="type-group">
        <legend class="type-label">Visitor Type</legend>
        <div class="type-options">

          <label class="type-option">
            <input type="radio" name="visitor_type" value="INDIVIDUAL" <?= $isGroup ? '' : 'checked' ?>>
            <span class="type-box">
              <span class="type-icon"><?= icon('person') ?></span>
              <span>
                <strong>Individual</strong>
                <small>One visitor</small>
              </span>
            </span>
          </label>

          <label class="type-option">
            <input type="radio" name="visitor_type" value="GROUP" <?= $isGroup ? 'checked' : '' ?>>
            <span class="type-box">
              <span class="type-icon"><?= icon('group') ?></span>
              <span>
                <strong>Group</strong>
                <small>Visiting together</small>
              </span>
            </span>
          </label>

        </div>
      </fieldset>

      <div class="form-group">
        <label for="qr_code">QR Code</label>
        <input type="text" id="qr_code" name="qr_code" placeholder="Enter visitor QR code" value="<?= htmlspecialchars($old['qr_code']) ?>" required autofocus>
      </div>

      <!-- GROUP DETAILS (only shown when Group is selected) -->
      <div class="group-fields" id="groupFields">

        <div class="form-group">
          <label for="group_name">Group / Organization Name</label>
          <input type="text" id="group_name" name="group_name" maxlength="150" value="<?= htmlspecialchars($old['group_name']) ?>" <?= $isGroup ? 'required' : '' ?>>
        </div>

        <div class="form-group">
          <label for="group_size">Number of People in the Group</label>
          <input type="number" id="group_size" name="group_size" min="2" max="<?= MAX_GROUP_SIZE ?>" step="1" value="<?= htmlspecialchars($old['group_size']) ?>" <?= $isGroup ? 'required' : '' ?>>
          <p class="hint">Include the leader. Name fields for the other members will appear below.</p>
        </div>

      </div>

      <div class="form-group">
        <label for="name" id="nameLabel"><?= $isGroup ? 'Group Leader / Contact Person' : 'Visitor Name' ?></label>
        <input type="text" id="name" name="name" placeholder="<?= $isGroup ? 'Name of the group leader' : 'Full name' ?>" value="<?= htmlspecialchars($old['name']) ?>" required>
      </div>

      <!-- MEMBER NAME FIELDS (generated from the number above) -->
      <div class="members-box" id="membersBox">
        <p class="members-title">Group Members <span id="membersCount"></span></p>
        <div id="membersList"></div>
      </div>

      <div class="form-group">
        <label for="purpose">Purpose</label>
        <input type="text" id="purpose" name="purpose" placeholder="Purpose of Visit" value="<?= htmlspecialchars($old['purpose']) ?>" required>
      </div>

      <div class="form-group">
        <label for="destination">Destination</label>
        <input type="text" id="destination" name="destination" placeholder="Where are they going?" value="<?= htmlspecialchars($old['destination']) ?>" required>
      </div>

      <div class="form-actions">
        <button type="submit" class="btn btn-primary" id="submitBtn"><?= $isGroup ? 'Register Group' : 'Register Visitor' ?></button>
      </div>

    </form>
  </div>

</main>

<script>
  // Auto-dismiss alerts after 5 seconds
  document.querySelectorAll('.alert').forEach(function (alertEl) {
    setTimeout(function () {
      alertEl.classList.add('hide');
      setTimeout(function () { alertEl.remove(); }, 400);
    }, 5000);
  });

  // Individual / Group switch + automatic member fields
  (function () {
    var MAX = <?= (int)MAX_GROUP_SIZE ?>;

    var form        = document.getElementById('visitorForm');
    var radios      = form.querySelectorAll('input[name="visitor_type"]');
    var groupName   = document.getElementById('group_name');
    var groupSize   = document.getElementById('group_size');
    var nameLabel   = document.getElementById('nameLabel');
    var nameInput   = document.getElementById('name');
    var submitBtn   = document.getElementById('submitBtn');
    var membersBox  = document.getElementById('membersBox');
    var membersList = document.getElementById('membersList');
    var membersCnt  = document.getElementById('membersCount');

    // names typed so far (kept when the number changes, or after a form error)
    var typed = <?= json_encode(array_values($old['members']), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    function isGroup() {
      return form.querySelector('input[name="visitor_type"]:checked').value === 'GROUP';
    }

    function saveTyped() {
      var inputs = membersList.querySelectorAll('input');
      if (!inputs.length) { return; }
      inputs.forEach(function (inp, i) { typed[i] = inp.value; });
    }

    function buildMembers() {
      saveTyped();
      membersList.innerHTML = '';

      var total = parseInt(groupSize.value, 10);
      var valid = isGroup() && total >= 2 && total <= MAX;

      membersBox.classList.toggle('has-members', valid);
      if (!valid) { membersCnt.textContent = ''; return; }

      var others = total - 1;   // the leader is already the "name" field above
      membersCnt.textContent = '(' + others + ' besides the leader)';

      for (var i = 0; i < others; i++) {
        var wrap  = document.createElement('div');
        wrap.className = 'form-group';

        var label = document.createElement('label');
        label.htmlFor = 'member_' + i;
        label.textContent = 'Member ' + (i + 2);

        var input = document.createElement('input');
        input.type = 'text';
        input.id = 'member_' + i;
        input.name = 'members[]';
        input.maxLength = 100;
        input.placeholder = 'Full name';
        input.required = true;
        input.value = typed[i] || '';

        wrap.appendChild(label);
        wrap.appendChild(input);
        membersList.appendChild(wrap);
      }
    }

    function apply() {
      var group = isGroup();

      form.classList.toggle('is-group', group);

      // hidden fields must not block the form from submitting
      groupName.required = group;
      groupSize.required = group;

      nameLabel.textContent = group ? 'Group Leader / Contact Person' : 'Visitor Name';
      nameInput.placeholder = group ? 'Name of the group leader' : 'Full name';
      submitBtn.textContent = group ? 'Register Group' : 'Register Visitor';

      buildMembers();
    }

    radios.forEach(function (r) { r.addEventListener('change', apply); });
    groupSize.addEventListener('input', buildMembers);
    apply();
  })();
</script>

</body>
</html>