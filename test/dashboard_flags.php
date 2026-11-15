<?php
// Shared by the Security, Officer and Admin dashboards and by flagged_feed.php.
// Builds the table rows for "Recent Logs" and "Flagged Activity".

function dash_h($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }

function dash_reason_label($r) {
  static $map = [
    'UNKNOWN_ID'     => 'ID not found',
    'QR_EXPIRED'     => 'QR expired',
    'FACE_MISMATCH'  => 'Face mismatch',
    'NOT_REGISTERED' => 'Not registered',
  ];
  return $map[$r] ?? (string)$r;
}

function dash_logs_rows($conn, $limit = 5) {
  $limit = max(1, min(20, (int)$limit));
  $html = '';
  $r = $conn->query("SELECT name, status, reason, flagged, timestamp FROM logs ORDER BY timestamp DESC, id DESC LIMIT $limit");
  while ($r && $row = $r->fetch_assoc()) {
    $st  = strtoupper((string)$row['status']);
    $cls = $st === 'IN' ? 'badge-in' : ($st === 'DENIED' ? 'badge-denied' : 'badge-out');
    $extra = ($st === 'DENIED' && !empty($row['reason']))
      ? '<span class="log-reason">' . dash_h(dash_reason_label($row['reason'])) . '</span>' : '';
    $flag = !empty($row['flagged']) ? ' <span class="flag-mark">⚑ FLAGGED</span>' : '';
    $html .= '<tr><td>' . dash_h($row['name']) . '</td>'
          .  '<td><span class="badge ' . $cls . '">' . dash_h($st) . '</span>' . $flag . $extra . '</td>'
          .  '<td>' . dash_h(date('M j, g:i A', strtotime($row['timestamp']))) . '</td></tr>';
  }
  return $html !== '' ? $html : '<tr><td colspan="3" class="empty">No activity yet</td></tr>';
}

function dash_flagged_rows($conn, $limit = 5) {
  $limit = max(1, min(20, (int)$limit));
  $html = '';
  $f = $conn->query("SELECT id_number, name, reason, denial_count, created_at FROM flagged_events ORDER BY created_at DESC, id DESC LIMIT $limit");
  while ($f && $row = $f->fetch_assoc()) {
    $html .= '<tr><td>' . dash_h($row['name']) . '<span class="log-reason">ID ' . dash_h($row['id_number']) . '</span></td>'
          .  '<td><span class="badge badge-denied">' . dash_h(dash_reason_label($row['reason'])) . '</span></td>'
          .  '<td>' . (int)$row['denial_count'] . '</td>'
          .  '<td>' . dash_h(date('M j, g:i A', strtotime($row['created_at']))) . '</td></tr>';
  }
  return $html !== '' ? $html : '<tr><td colspan="4" class="empty">No flagged activity</td></tr>';
}