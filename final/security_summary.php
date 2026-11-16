<?php
session_start();
include 'db.php';

// Only admin and security officer can open this page
if (empty($_SESSION['admin_logged_in']) && empty($_SESSION['officer_logged_in'])) {
  header("Location: login.php");
  exit;
}
header("Cache-Control: no-cache, no-store, must-revalidate");

// ---------- period (whitelisted, never taken straight from the URL) ----------
$periods = [
  'day'   => ['label' => 'Daily',   'days' => 1,  'name' => 'Today',        'prevName' => 'yesterday'],
  'week'  => ['label' => 'Weekly',  'days' => 7,  'name' => 'Last 7 days',  'prevName' => 'the 7 days before'],
  'month' => ['label' => 'Monthly', 'days' => 30, 'name' => 'Last 30 days', 'prevName' => 'the 30 days before'],
];
$p = $_GET['p'] ?? 'day';
if (!isset($periods[$p])) $p = 'day';

// Optional custom date range. Dates are checked strictly, so only YYYY-MM-DD ever reaches SQL.
function valid_date($s) {
  $d = DateTime::createFromFormat('Y-m-d', (string)$s);
  return ($d && $d->format('Y-m-d') === $s) ? $d : null;
}
$df = valid_date($_GET['df'] ?? '');
$dt = valid_date($_GET['dt'] ?? '');
$custom = false;
$span = 0;
if ($df && $dt && $df <= $dt) {
  $span = (int)$df->diff($dt)->days + 1;
  $custom = $span <= 366;
}
$dateNote = '';
if (!$custom && (($_GET['df'] ?? '') !== '' || ($_GET['dt'] ?? '') !== '')) {
  $dateNote = 'Please pick both a From and a To date (From must not be after To, and the range can be up to 366 days). Showing the selected tab instead.';
}

if ($custom) {
  $n = $span;
  $periodName = $df->format('M j, Y') . ' – ' . $dt->format('M j, Y');
  $prevName   = 'the ' . $n . ' day' . ($n > 1 ? 's' : '') . ' before';
  $curFrom  = "'" . $df->format('Y-m-d') . "'";
  $curTo    = "'" . $dt->format('Y-m-d') . "' + INTERVAL 1 DAY";
  $prevFrom = "'" . $df->format('Y-m-d') . "' - INTERVAL " . $n . " DAY";
  $prevTo   = "'" . $df->format('Y-m-d') . "'";
  $fileTag  = $df->format('Ymd') . '-' . $dt->format('Ymd');
} else {
  $n = $periods[$p]['days'];
  $periodName = $periods[$p]['name'];
  $prevName   = $periods[$p]['prevName'];
  // SQL ranges built only from whitelisted integers
  $curFrom  = "CURDATE() - INTERVAL " . ($n - 1) . " DAY";
  $curTo    = "CURDATE() + INTERVAL 1 DAY";
  $prevFrom = "CURDATE() - INTERVAL " . (2 * $n - 1) . " DAY";
  $prevTo   = "CURDATE() - INTERVAL " . ($n - 1) . " DAY";
  $fileTag  = $p;
}

// Guard filter (whole page) and search text (attempts list). Values are escaped before they go into SQL.
$gFilter = trim((string)($_GET['g'] ?? ''));
$search  = function_exists('mb_substr') ? mb_substr(trim((string)($_GET['q'] ?? '')), 0, 60) : substr(trim((string)($_GET['q'] ?? '')), 0, 60);
$gw = '';
if ($gFilter !== '') {
  $gw = ($gFilter === '(not recorded)')
    ? " AND (scanned_by IS NULL OR scanned_by = '')"
    : " AND scanned_by = '" . $conn->real_escape_string($gFilter) . "'";
}

function stats($conn, $from, $to, $extra = '') {
  $r = ['entries' => 0, 'exits' => 0, 'denied' => 0, 'flagged' => 0, 'visitors' => 0];
  try {
    $q = $conn->query("SELECT
        COALESCE(SUM(type='ENTRY' AND status<>'DENIED'),0) AS e,
        COALESCE(SUM(type='EXIT' AND status<>'DENIED'),0) AS x,
        COALESCE(SUM(status='DENIED'),0) AS d,
        COALESCE(SUM(flagged=1),0) AS f,
        COALESCE(SUM(type='ENTRY' AND status<>'DENIED' AND role='Visitor'),0) AS v
      FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs WHERE timestamp >= $from AND timestamp < $to$extra");
    if ($q && ($row = $q->fetch_assoc())) {
      $r = ['entries' => (int)$row['e'], 'exits' => (int)$row['x'], 'denied' => (int)$row['d'],
            'flagged' => (int)$row['f'], 'visitors' => (int)$row['v']];
    }
  } catch (Throwable $e) { error_log('summary stats: ' . $e->getMessage()); }
  return $r;
}

function rows($conn, $sql) {
  $out = [];
  try {
    $q = $conn->query($sql);
    while ($q && $row = $q->fetch_assoc()) $out[] = $row;
  } catch (Throwable $e) { error_log('summary rows: ' . $e->getMessage()); }
  return $out;
}

$cur  = stats($conn, $curFrom, $curTo, $gw);
$prev = stats($conn, $prevFrom, $prevTo, $gw);

// Guards for the filter drop-down
$guardOptions = rows($conn, "SELECT DISTINCT COALESCE(NULLIF(scanned_by,''),'(not recorded)') AS g FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs ORDER BY g");

// Busiest hour (entries + exits)
$busy = rows($conn, "SELECT HOUR(timestamp) AS h, COUNT(*) AS c FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs
  WHERE type IN ('ENTRY','EXIT') AND status<>'DENIED' AND timestamp >= $curFrom AND timestamp < $curTo$gw
  GROUP BY h ORDER BY c DESC LIMIT 1");
$busiestLabel = '—';
if ($busy) {
  $h = (int)$busy[0]['h'];
  $busiestLabel = date('g A', strtotime(sprintf('%02d:00', $h))) . ' – ' . date('g A', strtotime(sprintf('%02d:00', ($h + 1) % 24)))
                . ' (' . (int)$busy[0]['c'] . ' scans)';
}

// Denial reasons
$reasonNames = ['UNKNOWN_ID' => 'ID not found', 'QR_EXPIRED' => 'QR expired', 'FACE_MISMATCH' => 'Face mismatch', 'NOT_REGISTERED' => 'Not registered'];
$reasons = rows($conn, "SELECT COALESCE(NULLIF(reason,''),'OTHER') AS reason, COUNT(*) AS c FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs
  WHERE status='DENIED' AND timestamp >= $curFrom AND timestamp < $curTo$gw
  GROUP BY reason ORDER BY c DESC");

// Unauthorized access attempts: the latest denied scans, one by one.
// The "who" columns are looked up so this works with whatever your logs table calls them.
// If your names differ, add them to these two lists.
$nameCol = 'name';      // alias from access_logs.name_snapshot
$idCol   = 'id_number'; // access_logs.id_number
// Reason filter (checked against the known reasons) and search text apply to this list only
$rFilter = (string)($_GET['r'] ?? '');
if ($rFilter !== 'OTHER' && !isset($reasonNames[$rFilter])) $rFilter = '';
$aw = '';
if ($rFilter === 'OTHER') {
  $aw .= " AND (reason IS NULL OR reason = '' OR reason NOT IN ('UNKNOWN_ID','QR_EXPIRED','FACE_MISMATCH','NOT_REGISTERED'))";
} elseif ($rFilter !== '') {
  $aw .= " AND reason = '" . $conn->real_escape_string($rFilter) . "'";
}
if ($search !== '') {
  $like  = "'%" . addcslashes($conn->real_escape_string($search), '%_') . "%'";
  $parts = ["scanned_by LIKE $like", "role LIKE $like"];
  if ($nameCol) $parts[] = "`$nameCol` LIKE $like";
  if ($idCol)   $parts[] = "CAST(`$idCol` AS CHAR) LIKE $like";
  // typing "face" also finds the "Face mismatch" reason
  $hit = [];
  foreach ($reasonNames as $k => $label) if (stripos($label, $search) !== false) $hit[] = "'" . $k . "'";
  if ($hit) $parts[] = "reason IN (" . implode(',', $hit) . ")";
  $aw .= " AND (" . implode(' OR ', $parts) . ")";
}
$showAll = !empty($_GET['all']);
$attemptLimit = $showAll ? 500 : (($rFilter !== '' || $search !== '') ? 50 : 10);
$attWhere = "status='DENIED' AND timestamp >= $curFrom AND timestamp < $curTo$gw$aw";
$cnt = rows($conn, "SELECT COUNT(*) AS c FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs WHERE $attWhere");
$attTotal = $cnt ? (int)$cnt[0]['c'] : 0;
$attempts = rows($conn, "SELECT timestamp, role, reason, scanned_by, flagged"
  . ($nameCol ? ", `$nameCol` AS who_name" : "")
  . ($idCol   ? ", `$idCol` AS who_id"     : "")
  . " FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs WHERE $attWhere ORDER BY timestamp DESC LIMIT $attemptLimit");

// Flagged scans (any type, not only denied): the latest ones, who and where.
// $cur['flagged'] already holds the total for this period and guard filter.
$flaggedRows = rows($conn, "SELECT timestamp, type, status, role, reason, scanned_by"
  . ($nameCol ? ", `$nameCol` AS who_name" : "")
  . ($idCol   ? ", `$idCol` AS who_id"     : "")
  . " FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs WHERE flagged=1 AND timestamp >= $curFrom AND timestamp < $curTo$gw"
  . " ORDER BY timestamp DESC LIMIT 20");

// What is filtered right now (shown on the printed report) and the filters the tabs should keep
$activeFilters = [];
if ($gFilter !== '') $activeFilters[] = 'Guard: ' . $gFilter;
if ($rFilter !== '') $activeFilters[] = 'Reason: ' . ($rFilter === 'OTHER' ? 'Other' : $reasonNames[$rFilter]);
if ($search !== '')  $activeFilters[] = 'Search: "' . $search . '"';
$keep = array_filter(['g' => $gFilter, 'r' => $rFilter, 'q' => $search], function ($v) { return $v !== ''; });

// Scans per guard
$guards = rows($conn, "SELECT COALESCE(NULLIF(scanned_by,''),'(not recorded)') AS guard,
    COALESCE(SUM(type='ENTRY' AND status<>'DENIED'),0) AS e, COALESCE(SUM(type='EXIT' AND status<>'DENIED'),0) AS x,
    COALESCE(SUM(status='DENIED'),0) AS d, COALESCE(SUM(flagged=1),0) AS f, COUNT(*) AS total
  FROM (SELECT a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status, CONCAT(UPPER(LEFT(COALESCE(a.person_type,''),1)), SUBSTRING(COALESCE(a.person_type,''),2)) AS role, a.reason, a.flagged, a.guard_snapshot AS scanned_by, a.name_snapshot AS name, a.id_number FROM access_logs a) logs WHERE timestamp >= $curFrom AND timestamp < $curTo$gw
  GROUP BY guard ORDER BY total DESC");


// Currently inside
$inside = ['users' => 0, 'visitors' => 0];
$q = rows($conn, "SELECT COUNT(*) AS c FROM people WHERE status='IN'");
if ($q) $inside['users'] = (int)$q[0]['c'];
$q = rows($conn, "SELECT COUNT(*) AS c FROM visitors WHERE status='IN'");
if ($q) $inside['visitors'] = (int)$q[0]['c'];

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

// Label for a scan row in the flagged list: Denied, Entry or Exit
function scanLabel($status, $type) {
  if ($status === 'DENIED') return 'Denied';
  return ucfirst(strtolower((string)$type));
}

// Change vs previous period; for "denied" and "flagged" going up is bad
function trend($now, $before, $badIfUp = false) {
  if ($now == $before) return '<span class="tr flat">no change</span>';
  $up = $now > $before;
  $pct = $before > 0 ? round(abs($now - $before) / $before * 100) . '%' : 'new';
  $bad = $badIfUp ? $up : !$up;
  $cls = $bad ? 'bad' : 'good';
  return '<span class="tr ' . $cls . '">' . ($up ? '▲ ' : '▼ ') . $pct . '</span>';
}

// Where "Back" goes. The dashboard link adds ?from=admin or ?from=officer, and we remember it,
// because one browser can hold both an admin and an officer login at the same time.
$backMap = ['admin' => 'admin_dashboard.php', 'officer' => 'officer_dashboard.php'];
$from = $_GET['from'] ?? '';
$loggedIn = ['admin' => !empty($_SESSION['admin_logged_in']), 'officer' => !empty($_SESSION['officer_logged_in'])];
if (isset($loggedIn[$from]) && $loggedIn[$from]) {
  // the link says which role is using the page: trust it (only if that role is really logged in)
  $_SESSION['summary_from'] = $from;
} else {
  $from = $_SESSION['summary_from'] ?? '';
  if (!isset($loggedIn[$from]) || !$loggedIn[$from]) {
    // no usable hint: use the role that logged in most recently
    $last = $_SESSION['last_role'] ?? '';
    $from = (isset($loggedIn[$last]) && $loggedIn[$last]) ? $last : ($loggedIn['admin'] ? 'admin' : 'officer');
  }
}
$back = $backMap[$from];

// the current view as link parameters (used by Show all / Show fewer)
$stateBase = array_merge($keep, $custom ? ['df' => $df->format('Y-m-d'), 'dt' => $dt->format('Y-m-d')] : ['p' => $p], ['from' => $from]);

// Sidebar links for the role that opened this page
$navMap = [
  'admin'   => ['dash' => 'admin_dashboard.php',   'users' => 'users.php',         'sec' => 'manage_security.php', 'logs' => 'admin_logs.php',   'logout' => 'admin_logout.php',   'label' => 'Administrator'],
  'officer' => ['dash' => 'officer_dashboard.php', 'users' => 'officer_users.php', 'sec' => 'officer_security.php', 'logs' => 'officer_logs.php', 'logout' => 'officer_logout.php', 'label' => 'Security Officer'],
];
$nav = $navMap[$from];

function icon($name) {
  $paths = [
    'home'   => '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    'user'   => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    'lock'   => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    'list'   => '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    'chart'  => '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    'logout' => '<path d="M9 21H5V3h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
    'in'     => '<path d="M3 12h12M10 7l5 5-5 5"/><path d="M15 4h4a2 2 0 012 2v12a2 2 0 01-2 2h-4"/>',
    'out'    => '<path d="M21 12H9M14 7l-5 5 5 5"/><path d="M9 4H5a2 2 0 00-2 2v12a2 2 0 002 2h4"/>',
    'alert'  => '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5h.01"/>',
    'flag'   => '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
    'visitor'=> '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6 16c.5-1.5 1.7-2 3-2s2.5.5 3 2M15 10h3M15 13h3"/>',
    'clock'  => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    'shield' => '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  ];
  return '<svg viewBox="0 0 24 24" aria-hidden="true">' . $paths[$name] . '</svg>';
}

// ---------- data for the downloadable PDF (same numbers as the page) ----------
function pdfText($s) {   // the PDF's built-in font has no fancy dashes or dots
  return strtr((string)$s, ['–' => '-', '—' => '-', '·' => '|', '▲' => '', '▼' => '']);
}
function trendText($now, $before) {
  if ($now == $before) return 'no change';
  $pct = $before > 0 ? round(abs($now - $before) / $before * 100) . '%' : 'new';
  return ($now > $before ? 'up ' : 'down ') . $pct;
}
$pdfAttempts = [];
foreach ($attempts as $at) {
  $rk   = ($at['reason'] === null || $at['reason'] === '') ? 'OTHER' : $at['reason'];
  $name = trim((string)($at['who_name'] ?? ''));
  $id   = trim((string)($at['who_id'] ?? ''));
  $who  = $name !== '' ? ($id !== '' ? "$name (ID: $id)" : $name) : ($id !== '' ? "$id (not matched)" : 'Unknown');
  $pdfAttempts[] = [
    date('M j, Y, g:i A', strtotime($at['timestamp'])),
    pdfText($who),
    pdfText($at['role'] ?: '-'),
    pdfText($reasonNames[$rk] ?? ($rk === 'OTHER' ? 'Other' : $rk)),
    pdfText($at['scanned_by'] !== null && $at['scanned_by'] !== '' ? $at['scanned_by'] : '(not recorded)'),
    !empty($at['flagged']) ? 'Yes' : '-',
  ];
}
$pdfFlagged = [];
foreach ($flaggedRows as $f) {
  $fname = trim((string)($f['who_name'] ?? ''));
  $fid   = trim((string)($f['who_id'] ?? ''));
  $fwho  = $fname !== '' ? ($fid !== '' ? "$fname (ID: $fid)" : $fname) : ($fid !== '' ? "$fid (not matched)" : 'Unknown');
  $frk   = ($f['reason'] === null || $f['reason'] === '') ? '' : $f['reason'];
  $pdfFlagged[] = [
    date('M j, Y, g:i A', strtotime($f['timestamp'])),
    pdfText($fwho),
    pdfText($f['role'] ?: '-'),
    scanLabel($f['status'], $f['type']),
    $frk !== '' ? pdfText($reasonNames[$frk] ?? $frk) : '-',
    pdfText($f['scanned_by'] !== null && $f['scanned_by'] !== '' ? $f['scanned_by'] : '(not recorded)'),
  ];
}
$pdfReasons = [];
foreach ($reasons as $r) $pdfReasons[] = [pdfText($reasonNames[$r['reason']] ?? $r['reason']), (int)$r['c']];
$pdfGuards = [];
foreach ($guards as $g) $pdfGuards[] = [pdfText($g['guard']), (int)$g['e'], (int)$g['x'], (int)$g['d'], (int)$g['f'], (int)$g['total']];

$pdfData = [
  'title'     => 'Security Summary Report',
  'period'    => pdfText($periodName . ' (compared with ' . $prevName . ')'),
  'filters'   => $activeFilters ? pdfText(implode(' | ', $activeFilters)) : 'None',
  'generated' => date('F j, Y, g:i A') . ' | ' . $nav['label'],
  'file'      => 'Security-Summary-' . $fileTag . '-' . date('Y-m-d') . '.pdf',
  'cards'     => [
    ['Entries',  $cur['entries'],  trendText($cur['entries'],  $prev['entries'])],
    ['Exits',    $cur['exits'],    trendText($cur['exits'],    $prev['exits'])],
    ['Denied',   $cur['denied'],   trendText($cur['denied'],   $prev['denied'])],
    ['Flagged',  $cur['flagged'],  trendText($cur['flagged'],  $prev['flagged'])],
    ['Visitors', $cur['visitors'], trendText($cur['visitors'], $prev['visitors'])],
    ['Busiest hour', pdfText($busiestLabel), ''],
  ],
  'inside'    => [['Students, staff and alumni', $inside['users']], ['Visitors', $inside['visitors']]],
  'reasons'   => $pdfReasons,
  'flagged'   => $pdfFlagged,
  'flagNote'  => 'Showing ' . count($flaggedRows) . ' of ' . $cur['flagged'] . ($cur['flagged'] > count($flaggedRows) ? ' (latest first).' : '.'),
  'attempts'  => $pdfAttempts,
  'attNote'   => 'Showing ' . count($attempts) . ' of ' . $attTotal . ($attTotal > count($attempts) ? ' (latest first). Use "Show all" on the page to include more.' : '.'),
  'guards'    => $pdfGuards,
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Summary</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root { --ink: #16233d; --navy: #1c3a5e; --line: #dce4ef; --muted: #8a9bb5; --gold: #f0b429; --gold-soft: #fffdf5; --gold-glow: 0 8px 24px rgba(240,180,41,0.25); }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fafbfd; min-height: 100vh; display: flex; color: var(--ink); }
svg { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.sidebar { width: 220px; flex-shrink: 0; background: linear-gradient(180deg, #1c3a5e, #0f2440); border-right: 1px solid #0f2440; height: 100vh; position: sticky; top: 0; display: flex; flex-direction: column; align-items: stretch; padding: 24px 18px; gap: 12px; overflow-y: auto; }
.sidebar .logo { display: flex; justify-content: center; }
.sidebar .logo img { width: 44px; height: 44px; border-radius: 12px; object-fit: cover; }
.sidebar-divider { width: 100%; height: 1px; background: rgba(255,255,255,0.12); margin: 4px 0; }
.sidebar .nav-item { display: flex; align-items: center; gap: 14px; width: 100%; color: #fff; text-decoration: none; font-size: 14px; font-weight: 500; white-space: nowrap; position: relative; }
.sidebar .nav-icon { width: 44px; height: 44px; border-radius: 12px; flex-shrink: 0; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12); display: flex; align-items: center; justify-content: center; transition: background .2s, border-color .2s, transform .2s; }
.sidebar .nav-icon svg { width: 20px; height: 20px; }
.sidebar .nav-label { color: rgba(255,255,255,0.85); overflow: hidden; text-overflow: ellipsis; }
.sidebar .nav-item:hover .nav-icon { background: rgba(240,180,41,0.18); border-color: var(--gold); transform: translateY(-1px); }
.sidebar .nav-item.active .nav-icon { background: rgba(240,180,41,0.25); border-color: var(--gold); }
.sidebar .nav-item.active .nav-label { color: #fff; font-weight: 600; }
.sidebar .nav-item:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; border-radius: 12px; }
.sidebar .logout-item { margin-top: auto; }
.main { flex: 1; min-width: 0; padding: 32px; }
.header { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.header-left h1 { font-size: 22px; font-weight: 600; }
.header-left p { font-size: 13px; color: var(--muted); margin-top: 4px; }
.header-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.admin-badge { font-size: 12px; color: #6b7a94; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--line); background: #fff; }
.admin-badge .role { color: #d97706; font-weight: 600; }
.btn { display: inline-block; text-decoration: none; border-radius: 12px; border: 1px solid var(--line); background: #fff; color: var(--ink); font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; padding: 11px 20px; transition: transform .15s, background .15s, border-color .15s, box-shadow .15s; }
.btn:hover { transform: translateY(-2px); background: var(--gold-soft); border-color: var(--gold); box-shadow: var(--gold-glow); }
.btn:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }
.btn-primary { background: var(--navy); border-color: var(--navy); color: #fff; }
.btn-primary:hover { background: var(--ink); border-color: var(--gold); }
.tabs { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #fff; padding: 20px; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); transition: border-color .2s, box-shadow .2s; }
.card:hover { border-color: var(--gold); box-shadow: var(--gold-glow); }
a.card { display: block; text-decoration: none; color: inherit; cursor: pointer; }
a.card:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }
.card .icon { width: 40px; height: 40px; margin-bottom: 12px; border-radius: 12px; border: 2px dashed #c7d7ec; background: #f4f7fb; display: flex; align-items: center; justify-content: center; color: var(--navy); }
.card .icon svg { width: 20px; height: 20px; }
.card small { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.card h2 { font-size: 32px; font-weight: 700; margin: 8px 0 4px; color: var(--navy); }
.card h2.small-text { font-size: 15px; line-height: 1.5; margin-top: 12px; }
.tr { font-size: 12px; font-weight: 600; }
.tr.good { color: #16a34a; } .tr.bad { color: #dc2626; } .tr.flat { color: var(--muted); }
.sections { display: flex; gap: 16px; margin-bottom: 24px; }
.section, .section-full { background: #fff; border-radius: 14px; border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(22,58,94,0.05); padding: 20px; }
.section { flex: 1; min-width: 0; }
.section-full { margin-bottom: 24px; }
.section-full#flagged { scroll-margin-top: 16px; border-left: 4px solid var(--gold); }
.section h3, .section-full h3 { font-size: 14px; font-weight: 600; margin-bottom: 16px; }
.section-full .hint { font-size: 12px; color: var(--muted); margin: -10px 0 14px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; color: #96a6c0; text-transform: uppercase; letter-spacing: 0.06em; padding: 0 12px 10px 0; white-space: nowrap; }
td { padding: 10px 12px 10px 0; border-top: 1px solid #eef2f8; font-size: 13px; color: #3c4a63; vertical-align: top; }
tr:hover td { color: var(--ink); }
td.r, th.r { text-align: right; }
td .sub { display: block; font-size: 11px; color: var(--muted); margin-top: 2px; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-security { background: #eef3fa; color: var(--navy); }
.badge-denied { background: #fdeaea; color: #dc2626; }
.badge-warn { background: #fff4db; color: #b45309; }
.badge-ok { background: #e8f8ef; color: #16a34a; }
.empty { color: #b7c3d6; font-size: 13px; padding: 12px 0; }
.filters { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 24px; background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 16px; }
.filters label { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.filters label.grow { flex: 1; min-width: 200px; }
.filters select, .filters input[type="date"], .filters input[type="search"] { font: inherit; font-size: 13px; color: var(--ink); padding: 9px 12px; border: 1px solid var(--line); border-radius: 10px; background: #fff; min-width: 140px; }
.filters input[type="search"] { width: 100%; }
.filters select:focus, .filters input:focus { outline: 2px solid var(--gold); outline-offset: 1px; }
.btn-sm { padding: 9px 16px; }
.notice { background: #fff4db; border: 1px solid #f6d58a; color: #7a4b05; border-radius: 12px; padding: 12px 16px; font-size: 13px; margin-bottom: 16px; }
.print-head { display: none; }
.more-link { margin-top: 12px; font-size: 12px; }
.more-link a { color: var(--muted); text-decoration: none; }
.more-link a:hover { color: var(--ink); text-decoration: underline; }
@media (max-width: 860px) {
  .sidebar { width: 64px; padding: 24px 10px; }
  .sidebar .nav-label { display: none; }
  .main { padding: 20px; }
  .sections { flex-direction: column; }
}
@media (prefers-reduced-motion: reduce) { .btn, .card, .sidebar .nav-icon { transition: none; } }
@page { size: A4; margin: 14mm; }
@media print {
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .sidebar, .no-print, .tabs, .filters, .header { display: none !important; }
  .main { padding: 0; }
  body { background: #fff; display: block; }
  .print-head { display: block; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 2px solid var(--navy); }
  .print-head h2 { font-size: 20px; color: var(--navy); margin-bottom: 6px; }
  .print-head p { font-size: 12px; color: #3c4a63; margin-top: 2px; }
  .card, .section, .section-full { box-shadow: none; break-inside: avoid; }
  .cards { grid-template-columns: repeat(3, 1fr); }
  .sections { flex-direction: row; }
  tr { break-inside: avoid; }
}
</style>
</head>
<body>

<nav class="sidebar" aria-label="Main">
  <div class="logo"><img src="lego.png" alt="Lego"></div>
  <div class="sidebar-divider"></div>
  <a class="nav-item" href="<?= h($nav['dash']) ?>" data-tip="Dashboard" aria-label="Dashboard"><span class="nav-icon"><?= icon('home') ?></span><span class="nav-label">Dashboard</span></a>
  <a class="nav-item" href="<?= h($nav['users']) ?>" data-tip="Users" aria-label="Users"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Users</span></a>
  <a class="nav-item" href="<?= h($nav['sec']) ?>" data-tip="Security Accounts" aria-label="Security Accounts"><span class="nav-icon"><?= icon('lock') ?></span><span class="nav-label">Security Accounts</span></a>
  <a class="nav-item" href="<?= h($nav['logs']) ?>" data-tip="Access Logs" aria-label="Access Logs"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Access Logs</span></a>
  <a class="nav-item active" href="security_summary.php?from=<?= h($from) ?>" data-tip="Security Summary" aria-label="Security Summary" aria-current="page"><span class="nav-icon"><?= icon('chart') ?></span><span class="nav-label">Security Summary</span></a>
  <a class="nav-item" href="authentication_logs.php?from=<?= h($from) ?>" data-tip="Login Activity" aria-label="Login Activity"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Login Activity</span></a>
  <a class="nav-item" href="activity_logs.php" data-tip="Security Activity" aria-label="Security Activity"><span class="nav-icon"><?= icon('list') ?></span><span class="nav-label">Security Activity</span></a>
  <a class="nav-item" href="active_sessions.php?from=<?= h($from) ?>" data-tip="Active Sessions" aria-label="Active Sessions"><span class="nav-icon"><?= icon('user') ?></span><span class="nav-label">Active Sessions</span></a>
  <a class="nav-item logout-item" href="<?= h($nav['logout']) ?>" data-tip="Logout" aria-label="Logout"><span class="nav-icon"><?= icon('logout') ?></span><span class="nav-label">Logout</span></a>
</nav>

<main class="main">

  <div class="header">
    <div class="header-left">
      <h1>Security Summary</h1>
      <p><?= h($periodName) ?> · compared with <?= h($prevName) ?> · <?= date('l, F j, Y') ?></p>
    </div>
    <div class="header-right no-print">
      <div class="admin-badge">Logged in as <span class="role"><?= h($nav['label']) ?></span></div>
      <button class="btn btn-primary" type="button" id="pdfBtn" title="Downloads this report as a PDF file">Generate PDF</button>
    </div>
  </div>

  <div class="print-head">
    <h2>Security Summary Report</h2>
    <p>Period: <?= h($periodName) ?> · compared with <?= h($prevName) ?></p>
    <p>Filters: <?= $activeFilters ? h(implode(' · ', $activeFilters)) : 'none' ?></p>
    <p>Generated <?= h(date('F j, Y, g:i A')) ?> · <?= h($nav['label']) ?></p>
  </div>

  <div class="tabs">
    <?php foreach ($periods as $key => $info): ?>
      <a class="btn <?= ($key === $p && !$custom) ? 'btn-primary' : '' ?>" href="?<?= h(http_build_query(array_merge($keep, ['p' => $key, 'from' => $from]))) ?>"><?= h($info['label']) ?></a>
    <?php endforeach; ?>
  </div>

  <?php if ($dateNote): ?><div class="notice no-print"><?= h($dateNote) ?></div><?php endif; ?>

  <form class="filters no-print" method="get">
    <input type="hidden" name="from" value="<?= h($from) ?>">
    <?php if (!$custom): ?><input type="hidden" name="p" value="<?= h($p) ?>"><?php endif; ?>
    <label>From
      <input type="date" name="df" value="<?= $custom ? h($df->format('Y-m-d')) : '' ?>">
    </label>
    <label>To
      <input type="date" name="dt" value="<?= $custom ? h($dt->format('Y-m-d')) : '' ?>">
    </label>
    <label>Guard
      <select name="g">
        <option value="">All guards</option>
        <?php foreach ($guardOptions as $go): ?>
          <option value="<?= h($go['g']) ?>" <?= $gFilter === $go['g'] ? 'selected' : '' ?>><?= h($go['g']) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label>Reason (attempts list)
      <select name="r">
        <option value="">All reasons</option>
        <?php foreach ($reasonNames as $k => $label): ?>
          <option value="<?= h($k) ?>" <?= $rFilter === $k ? 'selected' : '' ?>><?= h($label) ?></option>
        <?php endforeach; ?>
        <option value="OTHER" <?= $rFilter === 'OTHER' ? 'selected' : '' ?>>Other</option>
      </select>
    </label>
    <label class="grow">Search (attempts list)
      <input type="search" name="q" maxlength="60" placeholder="Name, ID, role, guard or reason" value="<?= h($search) ?>">
    </label>
    <button class="btn btn-primary btn-sm" type="submit">Apply</button>
    <a class="btn btn-sm" href="?p=<?= h($p) ?>&amp;from=<?= h($from) ?>">Clear</a>
  </form>

  <div class="cards">
    <div class="card"><div class="icon"><?= icon('in') ?></div><small>Entries</small><h2><?= $cur['entries'] ?></h2><?= trend($cur['entries'], $prev['entries']) ?></div>
    <div class="card"><div class="icon"><?= icon('out') ?></div><small>Exits</small><h2><?= $cur['exits'] ?></h2><?= trend($cur['exits'], $prev['exits']) ?></div>
    <div class="card"><div class="icon"><?= icon('alert') ?></div><small>Denied</small><h2><?= $cur['denied'] ?></h2><?= trend($cur['denied'], $prev['denied'], true) ?></div>
    <a class="card" href="#flagged" title="Jump to the flagged scans"><div class="icon"><?= icon('flag') ?></div><small>Flagged</small><h2><?= $cur['flagged'] ?></h2><?= trend($cur['flagged'], $prev['flagged'], true) ?></a>
    <div class="card"><div class="icon"><?= icon('visitor') ?></div><small>Visitors</small><h2><?= $cur['visitors'] ?></h2><?= trend($cur['visitors'], $prev['visitors']) ?></div>
    <div class="card"><div class="icon"><?= icon('clock') ?></div><small>Busiest hour</small><h2 class="small-text"><?= h($busiestLabel) ?></h2></div>
  </div>

  <div class="sections">
    <div class="section">
      <h3>Currently Inside</h3>
      <div class="table-wrap">
        <table>
          <tbody>
            <tr><td>Students, staff and alumni</td><td class="r"><strong><?= $inside['users'] ?></strong></td></tr>
            <tr><td>Visitors</td><td class="r"><strong><?= $inside['visitors'] ?></strong></td></tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="section">
      <h3>Why Scans Were Denied</h3>
      <div class="table-wrap">
        <table>
          <tbody>
          <?php if (!$reasons): ?>
            <tr><td class="empty">No denials in this period</td></tr>
          <?php else: foreach ($reasons as $r): ?>
            <tr><td><span class="badge badge-denied"><?= h($reasonNames[$r['reason']] ?? $r['reason']) ?></span></td><td class="r"><strong><?= (int)$r['c'] ?></strong></td></tr>
          <?php endforeach; endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="section-full" id="flagged">
    <h3>Flagged Scans</h3>
    <p class="hint">Scans marked as suspicious, for review: who, what kind of scan, why and which guard. Newest first.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Date &amp; Time</th><th>Who</th><th>Role</th><th>Scan</th><th>Reason</th><th>Guard</th></tr></thead>
        <tbody>
        <?php if (!$flaggedRows): ?>
          <tr><td colspan="6" class="empty">No flagged scans in this period</td></tr>
        <?php else: foreach ($flaggedRows as $f):
          $fname = trim((string)($f['who_name'] ?? ''));
          $fid   = trim((string)($f['who_id'] ?? ''));
          $frk   = ($f['reason'] === null || $f['reason'] === '') ? '' : $f['reason'];
        ?>
          <tr>
            <td><?= h(date('M j, Y, g:i A', strtotime($f['timestamp']))) ?></td>
            <td>
              <?php if ($fname !== ''): ?><?= h($fname) ?><?php if ($fid !== ''): ?><span class="sub">ID: <?= h($fid) ?></span><?php endif; ?>
              <?php elseif ($fid !== ''): ?><?= h($fid) ?><span class="sub">Not matched to a person</span>
              <?php else: ?><span class="sub">Unknown</span><?php endif; ?>
            </td>
            <td><?= h($f['role'] ?: '—') ?></td>
            <td><span class="badge <?= $f['status'] === 'DENIED' ? 'badge-denied' : 'badge-warn' ?>"><?= h(scanLabel($f['status'], $f['type'])) ?></span></td>
            <td><?= $frk !== '' ? h($reasonNames[$frk] ?? $frk) : '—' ?></td>
            <td><span class="badge badge-security"><?= h($f['scanned_by'] !== null && $f['scanned_by'] !== '' ? $f['scanned_by'] : '(not recorded)') ?></span></td>
          </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
    <p class="more-link no-print">
      <?php if ($cur['flagged'] > count($flaggedRows)): ?>Showing the latest <?= count($flaggedRows) ?> of <?= (int)$cur['flagged'] ?>.<?php endif; ?>
    </p>
  </div>

  <div class="section-full">
    <h3>Unauthorized Access Attempts</h3>
    <p class="hint">Denied scans at the gate: who, why, when and which guard. Newest first.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Date &amp; Time</th><th>Who</th><th>Role</th><th>Reason</th><th>Guard</th><th>Flagged</th></tr></thead>
        <tbody>
        <?php if (!$attempts): ?>
          <tr><td colspan="6" class="empty"><?= $activeFilters ? 'No unauthorized attempts match these filters' : 'No unauthorized attempts in this period' ?></td></tr>
        <?php else: foreach ($attempts as $at):
          $rk   = ($at['reason'] === null || $at['reason'] === '') ? 'OTHER' : $at['reason'];
          $name = trim((string)($at['who_name'] ?? ''));
          $id   = trim((string)($at['who_id'] ?? ''));
        ?>
          <tr>
            <td><?= h(date('M j, Y, g:i A', strtotime($at['timestamp']))) ?></td>
            <td>
              <?php if ($name !== ''): ?><?= h($name) ?><?php if ($id !== ''): ?><span class="sub">ID: <?= h($id) ?></span><?php endif; ?>
              <?php elseif ($id !== ''): ?><?= h($id) ?><span class="sub">Not matched to a person</span>
              <?php else: ?><span class="sub">Unknown</span><?php endif; ?>
            </td>
            <td><?= h($at['role'] ?: '—') ?></td>
            <td><span class="badge badge-denied"><?= h($reasonNames[$rk] ?? ($rk === 'OTHER' ? 'Other' : $rk)) ?></span></td>
            <td><span class="badge badge-security"><?= h($at['scanned_by'] !== null && $at['scanned_by'] !== '' ? $at['scanned_by'] : '(not recorded)') ?></span></td>
            <td><?= !empty($at['flagged']) ? '<span class="badge badge-warn">Flagged</span>' : '—' ?></td>
          </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
    <p class="more-link no-print">
      <?php if ($showAll): ?>
        Showing <?= count($attempts) ?> of <?= $attTotal ?><?= $attTotal > count($attempts) ? ' (the latest 500)' : '' ?>.
        <a href="?<?= h(http_build_query($stateBase)) ?>">Show fewer</a>
      <?php elseif ($attTotal > count($attempts)): ?>
        Showing the latest <?= count($attempts) ?> of <?= $attTotal ?>.
        <a href="?<?= h(http_build_query($stateBase + ['all' => 1])) ?>">Show all</a>
      <?php endif; ?>
    </p>
  </div>

  <div class="section-full">
    <h3>Scans per Guard</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Guard</th><th class="r">Entries</th><th class="r">Exits</th><th class="r">Denied</th><th class="r">Flagged</th><th class="r">Total</th></tr></thead>
        <tbody>
        <?php if (!$guards): ?>
          <tr><td colspan="6" class="empty">No scans in this period</td></tr>
        <?php else: foreach ($guards as $g): ?>
          <tr>
            <td><span class="badge badge-security"><?= h($g['guard']) ?></span></td>
            <td class="r"><?= (int)$g['e'] ?></td>
            <td class="r"><?= (int)$g['x'] ?></td>
            <td class="r"><?= (int)$g['d'] ?></td>
            <td class="r"><?= (int)$g['f'] ?></td>
            <td class="r"><strong><?= (int)$g['total'] ?></strong></td>
          </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  </div>

</main>
<script>
// The print window suggests the page title as the file name
var baseTitle = document.title;
window.addEventListener('beforeprint', function () { document.title = 'Security-Summary-<?= h($fileTag) ?>-<?= date('Y-m-d') ?>'; });
window.addEventListener('afterprint',  function () { document.title = baseTitle; });
</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.31/jspdf.plugin.autotable.min.js"></script>
<script>
document.getElementById('pdfBtn').addEventListener('click', function () {
  if (!window.jspdf || !window.jspdf.jsPDF) {
    alert('The PDF tool could not be loaded (it needs an internet connection). Opening the print window instead: choose "Save as PDF".');
    window.print();
    return;
  }
  var D = <?= json_encode($pdfData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
  var doc = new window.jspdf.jsPDF({ unit: 'mm', format: 'a4' });
  var W = doc.internal.pageSize.getWidth(), M = 14, y = 16;
  var NAVY = [28, 58, 94];

  doc.setFont('helvetica', 'bold'); doc.setFontSize(18); doc.setTextColor(NAVY[0], NAVY[1], NAVY[2]);
  doc.text(D.title, M, y); y += 7;
  doc.setFont('helvetica', 'normal'); doc.setFontSize(10); doc.setTextColor(60, 74, 99);
  ['Period: ' + D.period, 'Filters: ' + D.filters, 'Generated: ' + D.generated].forEach(function (t) {
    var lines = doc.splitTextToSize(t, W - 2 * M);
    doc.text(lines, M, y); y += 5 * lines.length;
  });
  doc.setDrawColor(NAVY[0], NAVY[1], NAVY[2]); doc.setLineWidth(0.6); doc.line(M, y, W - M, y); y += 8;

  function section(title, head, body, opts) {
    if (y > 255) { doc.addPage(); y = 16; }
    doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(NAVY[0], NAVY[1], NAVY[2]);
    doc.text(title, M, y);
    if (opts && opts.note) {
      doc.setFont('helvetica', 'normal'); doc.setFontSize(8); doc.setTextColor(138, 155, 181);
      doc.text(opts.note, W - M, y, { align: 'right' });
    }
    if (!body.length) body = [[{ content: (opts && opts.empty) || 'Nothing in this period', colSpan: head.length, styles: { textColor: [150, 160, 180], halign: 'center' } }]];
    doc.autoTable({
      startY: y + 2, head: [head], body: body, margin: { left: M, right: M },
      styles: { fontSize: 9, cellPadding: 2, textColor: [60, 74, 99] },
      headStyles: { fillColor: NAVY, textColor: 255 },
      alternateRowStyles: { fillColor: [244, 247, 251] },
      columnStyles: (opts && opts.cols) || {}
    });
    y = doc.lastAutoTable.finalY + 9;
  }

  var right = { halign: 'right' };
  section('Overview', ['Measure', 'This period', 'Change'], D.cards.map(function (c) { return [c[0], String(c[1]), c[2]]; }));
  section('Currently Inside', ['Group', 'Count'], D.inside.map(function (r) { return [r[0], String(r[1])]; }), { cols: { 1: right } });
  section('Why Scans Were Denied', ['Reason', 'Count'], D.reasons.map(function (r) { return [r[0], String(r[1])]; }), { empty: 'No denials in this period', cols: { 1: right } });
  section('Flagged Scans', ['Date & Time', 'Who', 'Role', 'Scan', 'Reason', 'Guard'], D.flagged,
          { note: D.flagNote, empty: 'No flagged scans in this period' });
  section('Unauthorized Access Attempts', ['Date & Time', 'Who', 'Role', 'Reason', 'Guard', 'Flagged'], D.attempts,
          { note: D.attNote, empty: 'No unauthorized attempts in this period' });
  section('Scans per Guard', ['Guard', 'Entries', 'Exits', 'Denied', 'Flagged', 'Total'],
          D.guards.map(function (r) { return r.map(String); }),
          { empty: 'No scans in this period', cols: { 1: right, 2: right, 3: right, 4: right, 5: right } });

  var pages = doc.internal.getNumberOfPages();
  for (var i = 1; i <= pages; i++) {
    doc.setPage(i); doc.setFont('helvetica', 'normal'); doc.setFontSize(8); doc.setTextColor(138, 155, 181);
    doc.text('Page ' + i + ' of ' + pages, W - M, 290, { align: 'right' });
  }
  doc.save(D.file);
});
</script>
</body>
</html>