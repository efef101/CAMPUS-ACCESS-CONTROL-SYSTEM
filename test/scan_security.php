<?php
// Denial logging + suspicious-activity flagging.
// Rule: 3 or more DENIED scans of the same ID within 10 minutes = flagged.
const SUSPICIOUS_DENIALS    = 3;
const SUSPICIOUS_WINDOW_MIN = 10;
// Column name of the ID in your flagged_events table.
// If phpMyAdmin shows it as id_number, change this to 'id_number'.
const FLAGGED_ID_COL = 'id_number';

function record_denial($conn, $idNumber, $name, $role, $reason) {
  $result = ['suspicious' => false, 'count' => 1];
  try {
    // Keep long/garbage scanned text from breaking the inserts
    $idNumber = mb_substr((string)$idNumber, 0, 50);
    $name     = mb_substr((string)$name, 0, 100);

    // The guard who made this scan
    $by = mb_substr((string)($_SESSION['security_username'] ?? ''), 0, 50);

    // Ignore accidental double-reads of the same card within 3 seconds
    $d = $conn->prepare("SELECT id FROM logs WHERE id_number = ? AND status = 'DENIED' AND timestamp >= NOW() - INTERVAL 3 SECOND LIMIT 1");
    $d->bind_param('s', $idNumber);
    $d->execute();
    $isDup = $d->get_result()->num_rows > 0;

    $logId = 0;
    if (!$isDup) {
      $ins = $conn->prepare("INSERT INTO logs (id_number, name, role, status, type, reason, scanned_by, scanned_by_name) VALUES (?, ?, ?, 'DENIED', 'DENIED', ?, ?, ?)");
      $ins->bind_param('ssssss', $idNumber, $name, $role, $reason, $by, $by);
      $ins->execute();
      $logId = $conn->insert_id;
    }

    $c = $conn->prepare("SELECT COUNT(*) AS c FROM logs WHERE id_number = ? AND status = 'DENIED' AND timestamp >= NOW() - INTERVAL " . SUSPICIOUS_WINDOW_MIN . " MINUTE");
    $c->bind_param('s', $idNumber);
    $c->execute();
    $count = (int)$c->get_result()->fetch_assoc()['c'];
    $result['count'] = $count;

    if ($count >= SUSPICIOUS_DENIALS) {
      $result['suspicious'] = true;
      if ($logId) {
        $f = $conn->prepare("UPDATE logs SET flagged = 1 WHERE id = ?");
        $f->bind_param('i', $logId);
        $f->execute();
      }
      $col = FLAGGED_ID_COL;
      $e = $conn->prepare("SELECT id FROM flagged_events WHERE $col = ? AND created_at >= NOW() - INTERVAL " . SUSPICIOUS_WINDOW_MIN . " MINUTE LIMIT 1");
      $e->bind_param('s', $idNumber);
      $e->execute();
      $existing = $e->get_result()->fetch_assoc();
      if ($existing) {
        $u = $conn->prepare("UPDATE flagged_events SET denial_count = ? WHERE id = ?");
        $u->bind_param('ii', $count, $existing['id']);
        $u->execute();
      } else {
        $n = $conn->prepare("INSERT INTO flagged_events ($col, name, reason, denial_count) VALUES (?, ?, ?, ?)");
        $n->bind_param('sssi', $idNumber, $name, $reason, $count);
        $n->execute();
      }
    }
  } catch (Throwable $ex) {
    error_log('record_denial failed: ' . $ex->getMessage());
  }
  return $result;
}