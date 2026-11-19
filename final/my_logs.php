<?php
ini_set('session.gc_maxlifetime', '2592000');   // keep session data on the server long enough for "Keep me logged in"
session_start();
date_default_timezone_set('Asia/Manila');
include 'db.php';

const BIRTHDAY_COLUMN     = 'birthdate';
const MAX_FAILS_PER_ID    = 5;           
const MAX_FAILS_PER_IP    = 20;          
const IDLE_LIMIT      = 1800;      
const PER_PAGE        = 15;        
const REMEMBER_LIMIT  = 2592000;   // "Keep me logged in": 30 days

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

// ---- announcements (used by the page and by the live-update request) ----
function ann_fetch($conn, $role) {
  $items = []; $new = 0;
  try {
    $col = $conn->query("SHOW COLUMNS FROM announcements LIKE 'importance'");
    if ($col && $col->num_rows === 0) {
      $conn->query("ALTER TABLE announcements ADD COLUMN importance VARCHAR(10) NOT NULL DEFAULT 'Normal' AFTER audience");
    }
    $aud = ucfirst(strtolower(trim((string)$role)));
    $aq = $conn->prepare("SELECT id, title, message, importance, created_at FROM announcements
                          WHERE active = 1 AND (expires_at IS NULL OR expires_at >= CURDATE())
                            AND (audience = 'All' OR audience = ?)
                          ORDER BY (importance = 'Urgent') DESC, created_at DESC, id DESC LIMIT 5");
    $aq->bind_param('s', $aud);
    $aq->execute();
    $items = $aq->get_result()->fetch_all(MYSQLI_ASSOC);
    foreach ($items as &$an) {                       // "new" = posted in the last 3 days
      $an['is_new'] = (time() - strtotime($an['created_at'])) <= 3 * 86400;
      $an['urgent'] = ($an['importance'] ?? '') === 'Urgent';
      if ($an['is_new']) $new++;
    }
    unset($an);
  } catch (Throwable $ex) { /* table not created yet: no announcements */ }
  return ['items' => $items, 'new' => $new];
}

function ann_html($items, $newCount) {
  if (empty($items)) return '';
  $hasUrgent = false;
  foreach ($items as $x) { if ($x['urgent']) { $hasUrgent = true; break; } }
  $first = $items[0]; $rest = array_slice($items, 1);
  ob_start(); ?>
    <div class="card ann<?= $hasUrgent ? ' has-urgent' : '' ?>">
      <div class="ann-head">
        <h3>Announcements</h3>
        <?php if ($newCount > 0): ?><span class="ann-count"><?= (int)$newCount ?> new</span><?php endif; ?>
      </div>

      <div class="ann-main<?= $first['urgent'] ? ' urgent' : '' ?>">
        <b><?= e($first['title']) ?>
          <?php if ($first['urgent']): ?><span class="tag urgent">URGENT</span><?php endif; ?>
          <?php if ($first['is_new']): ?><span class="tag new">NEW</span><?php endif; ?></b>
        <p><?= e($first['message']) ?></p>
        <small><?= e(date('F j, Y', strtotime($first['created_at']))) ?></small>
      </div>

      <?php foreach ($rest as $a): ?>
        <details class="ann-more" data-key="<?= (int)$a['id'] ?>">
          <summary>
            <?= e($a['title']) ?>
            <?php if ($a['urgent']): ?><span class="tag urgent">URGENT</span><?php endif; ?>
            <?php if ($a['is_new']): ?><span class="tag new">NEW</span><?php endif; ?>
          </summary>
          <div class="body">
            <p><?= e($a['message']) ?></p>
            <small><?= e(date('F j, Y', strtotime($a['created_at']))) ?></small>
          </div>
        </details>
      <?php endforeach; ?>
    </div>
  <?php
  return ob_get_clean();
}

function faceSrc($v) {
  $v = trim((string)$v);
  if ($v === '') return null;
  return str_starts_with($v, 'data:image') ? $v : 'data:image/jpeg;base64,' . $v;
}

function validDate($s) {
  $d = DateTime::createFromFormat('Y-m-d', (string)$s);
  return ($d && $d->format('Y-m-d') === $s) ? $s : '';
}

function logout_member() {
  unset($_SESSION['member_id'], $_SESSION['member_time'], $_SESSION['member_remember']);
  session_regenerate_id(true);
}

function idle_limit() {
  return !empty($_SESSION['member_remember']) ? REMEMBER_LIMIT : IDLE_LIMIT;
}

function remember_cookie() {
  $cp = session_get_cookie_params();
  setcookie(session_name(), session_id(), [
    'expires'  => time() + REMEMBER_LIMIT,
    'path'     => $cp['path'],
    'domain'   => $cp['domain'],
    'secure'   => $cp['secure'],
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
}

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));

$notice = '';
$error  = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $action = $_POST['action'] ?? '';

  if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
    $error = 'Session expired. Please try again.';

  } elseif ($action === 'logout') {
    logout_member();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;

  } elseif ($action === 'login') {
    $idn = substr(trim($_POST['id_number'] ?? ''), 0, 64);
    $bd  = validDate(trim($_POST['birthday'] ?? ''));
    $ip  = $_SERVER['REMOTE_ADDR'] ?? '';

    // table that remembers failed logins (created automatically the first time)
    $conn->query("CREATE TABLE IF NOT EXISTS member_login_attempts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      id_number VARCHAR(64) NOT NULL,
      ip VARCHAR(45) NOT NULL,
      attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX (id_number, attempted_at),
      INDEX (ip, attempted_at)
    )");

    // Lock out after too many failed attempts (per ID number and per device address)
    $q = $conn->prepare("SELECT SUM(id_number = ?) AS by_id, SUM(ip = ?) AS by_ip
                         FROM member_login_attempts WHERE attempted_at >= NOW() - INTERVAL 15 MINUTE");
    $q->bind_param("ss", $idn, $ip);
    $q->execute();
    $att = $q->get_result()->fetch_assoc();

    if ((int)$att['by_id'] >= MAX_FAILS_PER_ID || (int)$att['by_ip'] >= MAX_FAILS_PER_IP) {
      $error = 'Too many failed attempts. Please wait 15 minutes and try again.';
    } else {
      $u = null;
      if ($idn !== '' && $bd !== '') {
        $stmt = $conn->prepare("SELECT id_number, " . BIRTHDAY_COLUMN . " AS bd FROM people WHERE id_number = ?");
        $stmt->bind_param("s", $idn);
        $stmt->execute();
        $u = $stmt->get_result()->fetch_assoc();
      }

      $stored = '';
      if ($u && !empty($u['bd'])) {
        $t = strtotime($u['bd']);
        if ($t) $stored = date('Y-m-d', $t);
      }

      if ($u && $stored !== '' && hash_equals($stored, $bd)) {
        $clr = $conn->prepare("DELETE FROM member_login_attempts WHERE id_number = ?");
        $clr->bind_param("s", $idn);
        $clr->execute();
        session_regenerate_id(true);
        $_SESSION['member_id']   = $u['id_number'];
        $_SESSION['member_time'] = time();
        $_SESSION['member_remember'] = !empty($_POST['remember']);
        if ($_SESSION['member_remember']) remember_cookie();
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
      }

      $rec = $conn->prepare("INSERT INTO member_login_attempts (id_number, ip) VALUES (?, ?)");
      $rec->bind_param("ss", $idn, $ip);
      $rec->execute();
      $error = 'ID number and birthday do not match.';
    }
  }
}

// ============================================================
// Live announcements (the page asks for this every few seconds).
// It does NOT refresh the idle timer, so the page still logs out after 30 minutes of no real use.
// ============================================================
if (isset($_GET['ann'])) {
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store');
  $okSession = !empty($_SESSION['member_id']) && (time() - ($_SESSION['member_time'] ?? 0) <= idle_limit());
  if (!$okSession) { http_response_code(401); echo json_encode(['ok' => false]); exit; }
  $mid = $_SESSION['member_id'];
  session_write_close();
  $st = $conn->prepare("SELECT role FROM people WHERE id_number = ?");
  $st->bind_param("s", $mid);
  $st->execute();
  $row = $st->get_result()->fetch_assoc();
  $a = ann_fetch($conn, $row['role'] ?? '');
  echo json_encode(['ok' => true, 'html' => ann_html($a['items'], $a['new'])], JSON_UNESCAPED_UNICODE);
  exit;
}

// ============================================================
// Idle timeout
// ============================================================
if (!empty($_SESSION['member_id'])) {
  if (time() - ($_SESSION['member_time'] ?? 0) > idle_limit()) {
    logout_member();
    $notice = 'You were logged out because of inactivity.';
  } else {
    $_SESSION['member_time'] = time();
    if (!empty($_SESSION['member_remember'])) remember_cookie();
  }
}

$loggedIn = !empty($_SESSION['member_id']);

// ============================================================
// LOGGED-IN DATA
// ============================================================
if ($loggedIn) {
  header('Cache-Control: no-store');
  $myId = $_SESSION['member_id'];

  $stmt = $conn->prepare("SELECT p.first_name, p.last_name, p.role, p.course, p.department, p.position, p.status, fd.image AS face_image FROM people p LEFT JOIN face_data fd ON fd.person_id = p.id WHERE p.id_number = ?");
  $stmt->bind_param("s", $myId);
  $stmt->execute();
  $me = $stmt->get_result()->fetch_assoc();
  if (!$me) { logout_member(); header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?')); exit; }

  $fullName = trim($me['first_name'] . ' ' . $me['last_name']);
  $info = array_values(array_filter([$me['course'] ?? '', $me['department'] ?? '', $me['position'] ?? ''], fn($x) => trim((string)$x) !== ''));
  $photo = faceSrc($me['face_image'] ?? '');

  // ----- announcements for this member's role (posted by Security Personnel) -----
  $ann = ann_fetch($conn, $me['role']);
  $announcements = $ann['items'];
  $newCount = $ann['new'];

  // ----- filters -----
  $today = date('Y-m-d');
  $all   = isset($_GET['all']);
  $from  = validDate($_GET['from'] ?? '');
  $to    = validDate($_GET['to'] ?? '');

  if (!$all && !isset($_GET['from']) && !isset($_GET['to'])) {   // default view: last 30 days
    $from = date('Y-m-d', strtotime('-29 days'));
    $to   = $today;
  }
  if ($all) { $from = ''; $to = ''; }
  if ($from && $to && $from > $to) { [$from, $to] = [$to, $from]; }

  $where = "id_number = ?";
  $types = "s";
  $args  = [$myId];
  if ($from) { $where .= " AND timestamp >= ?"; $types .= "s"; $args[] = $from . ' 00:00:00'; }
  if ($to)   { $where .= " AND timestamp < ?";  $types .= "s"; $args[] = date('Y-m-d', strtotime($to . ' +1 day')) . ' 00:00:00'; }

  // ----- summary -----
  $stmt = $conn->prepare("SELECT COUNT(*) AS total,
                                 COALESCE(SUM(status = 'IN'), 0)     AS ins,
                                 COALESCE(SUM(status = 'OUT'), 0)    AS outs,
                                 COALESCE(SUM(status = 'DENIED'), 0) AS denied
                          FROM (SELECT a.id, a.id_number, a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status FROM access_logs a) logs WHERE $where");
  $stmt->bind_param($types, ...$args);
  $stmt->execute();
  $sum = $stmt->get_result()->fetch_assoc();

  $total = (int)$sum['total'];
  $pages = max(1, (int)ceil($total / PER_PAGE));
  $page  = min(max(1, (int)($_GET['page'] ?? 1)), $pages);
  $offset = ($page - 1) * PER_PAGE;

  // ----- rows -----
  $limit = PER_PAGE;
  $stmt = $conn->prepare("SELECT status, type, timestamp FROM (SELECT a.id, a.id_number, a.logged_at AS timestamp, a.event AS type, CASE a.event WHEN 'ENTRY' THEN 'IN' WHEN 'EXIT' THEN 'OUT' ELSE 'DENIED' END AS status FROM access_logs a) logs WHERE $where ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?");
  $stmt->bind_param($types . 'ii', ...array_merge($args, [$limit, $offset]));
  $stmt->execute();
  $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

  function pageUrl($p) {
    global $all, $from, $to;
    $q = [];
    if ($all) { $q['all'] = 1; }
    else { if ($from) $q['from'] = $from; if ($to) $q['to'] = $to; }
    if ($p > 1) $q['page'] = $p;
    return '?' . http_build_query($q);
  }

  $presets = [
    'Today'        => ['from' => $today, 'to' => $today],
    'Last 7 days'  => ['from' => date('Y-m-d', strtotime('-6 days')), 'to' => $today],
    'Last 30 days' => ['from' => date('Y-m-d', strtotime('-29 days')), 'to' => $today],
    'This month'   => ['from' => date('Y-m-01'), 'to' => $today],
  ];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= $loggedIn ? 'My Logs' : 'Campus Access History' ?> | CACS</title>

  <style>
    *{ margin:0; padding:0; box-sizing:border-box; }

    html,
    body{
      width:100%;
      min-height:100%;
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      background:#fafbfd;
      color:#16233d;
    }

    body{ position:relative; }

    /* =========================
       BACKGROUND (same as index)
    ========================= */
    .background{ position:fixed; inset:0; z-index:0; overflow:hidden; }

    .background::before{
      content:'';
      position:absolute;
      inset:-30px;
      background:
        linear-gradient(rgba(15,36,64,0.58), rgba(15,36,64,0.84)),
        url('background (1).jpg') center/cover no-repeat;
      filter:blur(8px);
      transform:scale(1.08);
    }

    .container{
      position:relative;
      z-index:2;
      width:100%;
      min-height:100vh;
      display:flex;
      justify-content:center;
      align-items:center;
      padding:30px;
    }
    .container.top{ align-items:flex-start; }

    /* =========================
       LOGIN (landscape: text left, panel right)
    ========================= */
    .dashboard{
      width:100%;
      max-width:1200px;
      display:grid;
      grid-template-columns:1fr 470px;
      align-items:center;
      gap:40px;
    }

    .left{ padding-left:10px; }

    .eyebrow{
      display:inline-flex;
      align-items:center;
      gap:10px;
      padding:8px 16px 8px 8px;
      border-radius:999px;
      background:rgba(255,255,255,0.10);
      border:1px solid rgba(255,255,255,0.22);
      backdrop-filter:blur(6px);
      margin-bottom:22px;
    }
    .eyebrow .mono{
      width:28px; height:28px; border-radius:50%; overflow:hidden; background:#ffffff;
      display:flex; align-items:center; justify-content:center;
    }
    .eyebrow .mono img{ width:100%; height:100%; object-fit:cover; }
    .eyebrow span{
      font-size:12px; font-weight:700; letter-spacing:0.16em; text-transform:uppercase; color:#ffffff;
    }
    .eyebrow .divider-dot{ width:4px; height:4px; border-radius:50%; background:rgba(255,255,255,0.4); }
    .eyebrow .tagline{
      font-size:11px; font-weight:500; letter-spacing:0.04em; text-transform:none; color:rgba(255,255,255,0.65);
    }

    .left h1{
      font-size:64px; font-weight:700; line-height:0.95; letter-spacing:-3px;
      margin-bottom:18px; color:#ffffff;
    }
    .left .desc{
      font-size:15px; line-height:1.7; color:rgba(255,255,255,0.82); max-width:500px;
    }

    .panel{
      width:100%;
      padding:32px;
      border-radius:30px;
      background:rgba(255,255,255,0.97);
      border:1px solid rgba(255,255,255,0.8);
      box-shadow:0 15px 40px rgba(15,36,64,0.25), 0 0 35px rgba(88,130,190,0.10);
      text-align:left;
    }
    .panel-top{ text-align:center; margin-bottom:24px; }
    .panel-top img{ width:84px; height:84px; object-fit:contain; margin-bottom:12px; border-radius:50%; background:#fff; box-shadow:0 4px 14px rgba(22,35,61,0.12); }
    .panel-top h2{ font-size:26px; margin-bottom:4px; color:#16233d; }
    .panel-top p{ font-size:14px; color:#8a9bb5; }

    .field{ margin-bottom:16px; }
    label{ display:block; font-size:12px; font-weight:600; color:#6b7a94; margin:0 0 6px 4px; }
    input[type=text], input[type=date]{
      width:100%; padding:14px 16px; border-radius:16px;
      border:1px solid #dce4ef; background:#f4f7fb;
      font:16px inherit; font-family:inherit; color:#16233d;
      transition:border-color .25s, background .25s, box-shadow .25s;
    }
    input:focus{
      outline:none; border-color:#6d8fca; background:#ffffff;
      box-shadow:0 0 0 4px rgba(109,143,202,0.15);
    }

    /* input with a leading icon */
    .with-icon{ position:relative; }
    .with-icon svg{
      position:absolute; left:16px; top:50%; transform:translateY(-50%);
      width:18px; height:18px; stroke:#8a9bb5; fill:none; stroke-width:2;
      stroke-linecap:round; stroke-linejoin:round; pointer-events:none;
    }
    .with-icon input{ padding-left:44px; }

    .remember{
      display:flex; align-items:center; gap:8px; margin:2px 0 4px 4px;
      font-size:13px; font-weight:500; color:#6b7a94; cursor:pointer; user-select:none;
    }
    .remember input{ width:16px; height:16px; margin:0; accent-color:#2f5a96; cursor:pointer; }

    .submit{
      width:100%; margin-top:8px; padding:15px; border-radius:16px;
      border:1px solid #2f5a96; background:#2f5a96; color:#fff;
      font:600 16px inherit; font-family:inherit; cursor:pointer;
      transition:transform .25s, background .25s, box-shadow .25s;
    }
    .submit:hover{ transform:translateY(-2px); background:#264b80; box-shadow:0 8px 24px rgba(58,94,145,0.25); }

    .msg{ padding:12px 14px; border-radius:14px; font-size:13px; margin-bottom:16px; }
    .msg.err { background:#fdeaea; color:#b91c1c; border:1px solid #f3c1c1; }
    .msg.note{ background:#fff7e0; color:#92400e; border:1px solid #f0d58a; }

    .divider{ height:1px; background:#eef2f8; margin:22px 0 18px; }
    .reg-line{ text-align:center; font-size:14px; color:#6b7a94; }
    .reg-line a{ color:#315b96; font-weight:700; text-decoration:none; }
    .reg-line a:hover{ text-decoration:underline; }

    .footer{ margin-top:18px; text-align:center; font-size:10px; color:#a3b3cc; }

    /* =========================
       LOGGED-IN VIEW
    ========================= */
    .wrap{ width:100%; max-width:960px; margin:0 auto; }

    .bar{
      display:flex; justify-content:space-between; align-items:center;
      gap:12px; flex-wrap:wrap; margin-bottom:18px;
    }
    .bar .eyebrow{ margin-bottom:0; }
    .out-btn{
      padding:9px 22px; border-radius:999px; cursor:pointer;
      background:rgba(255,255,255,0.12); border:1px solid rgba(255,255,255,0.3);
      color:#fff; font:600 13px inherit; font-family:inherit;
      backdrop-filter:blur(6px); transition:background .25s;
    }
    .out-btn:hover{ background:rgba(255,255,255,0.22); }

    .card{
      background:rgba(255,255,255,0.97);
      border:1px solid rgba(255,255,255,0.8);
      border-radius:28px;
      padding:28px;
      margin-bottom:18px;
      box-shadow:0 15px 40px rgba(15,36,64,0.25), 0 0 35px rgba(88,130,190,0.10);
    }

    .top-row{ display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
    .avatar{
      width:76px; height:76px; border-radius:50%; object-fit:cover;
      border:3px solid #fff; box-shadow:0 2px 10px rgba(22,35,61,0.15); background:#dce4ef;
    }
    .who h2{ font-size:24px; }
    .meta{ font-size:13px; color:#6b7a94; margin-top:3px; line-height:1.5; }
    .chip{ display:inline-block; margin-top:10px; padding:4px 14px; border-radius:999px; font-size:12px; font-weight:700; }
    .chip.in { background:#e8f8ef; color:#16a34a; }
    .chip.out{ background:#eaf1fe; color:#2563eb; }

    .stats{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:18px; }
    .stat{
      background:rgba(255,255,255,0.97); border:1px solid rgba(255,255,255,0.8);
      border-radius:22px; padding:18px 20px; box-shadow:0 8px 24px rgba(15,36,64,0.18);
    }
    .stat b{ display:block; font-size:28px; color:#16233d; }
    .stat span{ font-size:11px; color:#8a9bb5; text-transform:uppercase; letter-spacing:0.08em; font-weight:600; }

    .presets{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; }
    .pill{
      padding:8px 16px; border-radius:999px; border:1px solid #dce4ef; background:#f4f7fb;
      font-size:13px; font-weight:600; color:#16233d; text-decoration:none;
      transition:all .25s;
    }
    .pill:hover{ background:#fff; border-color:#6d8fca; }
    .pill.on{ background:#1c3a5e; color:#fff; border-color:#1c3a5e; }

    .range{ display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap; }
    .range .field{ flex:1; min-width:150px; margin-bottom:0; }

    .btn{
      display:inline-block; padding:14px 22px; border-radius:18px; border:1px solid #1c3a5e;
      background:#1c3a5e; color:#fff; font:600 14px inherit; font-family:inherit;
      cursor:pointer; text-decoration:none; transition:transform .25s, background .25s;
    }
    .btn:hover{ transform:translateY(-2px); background:#16304f; }
    .btn.ghost{ background:#f4f7fb; color:#16233d; border-color:#dce4ef; }
    .btn.ghost:hover{ background:#fff; border-color:#6d8fca; }

    .tablewrap{ overflow-x:auto; }
    table{ width:100%; border-collapse:collapse; }
    th{ text-align:left; font-size:12px; color:#96a6c0; text-transform:uppercase; letter-spacing:0.06em; padding:0 0 12px; }
    td{ padding:14px 0; border-top:1px solid #eef2f8; font-size:15px; color:#3c4a63; white-space:nowrap; }
    .lbadge{ display:inline-block; padding:3px 12px; border-radius:20px; font-size:13px; font-weight:600; }
    .lbadge.in    { background:#e8f8ef; color:#16a34a; }
    .lbadge.out   { background:#eaf1fe; color:#2563eb; }
    .lbadge.denied{ background:#fdeaea; color:#dc2626; }
    .empty{ text-align:center; color:#b7c3d6; padding:30px 0; }

    .pager{ display:flex; justify-content:space-between; align-items:center; margin-top:18px; font-size:13px; color:#6b7a94; gap:8px; flex-wrap:wrap; }
    .pager .btn{ padding:10px 18px; }
    .pager .off{ opacity:.4; pointer-events:none; }

    /* ANNOUNCEMENTS */
    .ann{ margin-bottom:18px; border-left:4px solid #f0b429; }
    .ann.has-urgent{ border-left-color:#dc2626; }
    .ann-head{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:12px; }
    .ann-head h3{ font-size:15px; color:#16233d; }
    .ann-count{ font-size:12px; font-weight:700; color:#92400e; background:#fff3cd; border:1px solid #f0d58a; padding:3px 10px; border-radius:999px; }
    .tag{ display:inline-block; font-size:10px; font-weight:800; letter-spacing:.06em; padding:2px 8px; border-radius:999px; margin-left:8px; vertical-align:middle; }
    .tag.new{ background:#f0b429; color:#4a3200; }
    .tag.urgent{ background:#dc2626; color:#fff; }
    .ann-main{ text-align:left; }
    .ann-main b{ display:block; font-size:16px; color:#16233d; }
    .ann-main p, .ann-more p{ margin:6px 0; font-size:14px; line-height:1.55; color:#3c4a63; white-space:pre-line; word-break:break-word; }
    .ann-main small, .ann-more small{ font-size:12px; color:#96a6c0; }
    .ann-main.urgent{ background:#fdeaea; border:1px solid #f3c1c1; border-radius:12px; padding:12px 14px; }
    .ann-more{ border-top:1px solid #eef2f8; margin-top:10px; padding-top:2px; text-align:left; }
    .ann-more summary{ cursor:pointer; list-style:none; padding:10px 0; font-size:14px; font-weight:600; color:#16233d; display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
    .ann-more summary::-webkit-details-marker{ display:none; }
    .ann-more summary::after{ content:'+'; margin-left:auto; color:#96a6c0; font-size:18px; }
    .ann-more[open] summary::after{ content:'–'; }
    .ann-more .body{ padding-bottom:10px; }

    /* =========================
       RESPONSIVE
    ========================= */
    @media(max-width:950px){
      .container{ padding:25px; }
      .dashboard{ grid-template-columns:1fr; max-width:560px; gap:25px; }
      .left{ text-align:center; padding-left:0; }
      .eyebrow{ margin-left:auto; margin-right:auto; }
      .bar .eyebrow{ margin-left:0; margin-right:0; }
      .left h1{ font-size:46px; }
      .left .desc{ margin:auto; }
      .panel{ padding:32px; }
    }

    @media(max-width:640px){
      .stats{ grid-template-columns:repeat(2,1fr); }
      .card{ padding:20px; border-radius:24px; }
    }

    @media(max-width:500px){
      .container{ padding:18px; }
      .left h1{ font-size:38px; letter-spacing:-2px; }
      .eyebrow{ padding:7px 12px 7px 7px; }
      .eyebrow span{ font-size:9px; }
      .eyebrow .tagline, .eyebrow .divider-dot{ display:none; }
      .panel{ padding:25px; border-radius:28px; }
      .panel-top h2{ font-size:24px; }
    }
  </style>
</head>

<body>

<div class="background"></div>

<?php if (!$loggedIn): ?>
<!-- ========== MEMBER LOGIN ========== -->
<div class="container">
  <div class="dashboard">

    <!-- LEFT SIDE -->
    <div class="left">
      <div class="eyebrow">
        <span class="mono"><img src="logo.png" alt="CTU logo"></span>
        <span>Cebu Technological University</span>
        <span class="divider-dot"></span>
        <span class="tagline">Main Campus</span>
      </div>

      <h1>Campus Access<br>Control System</h1>

    </div>

    <!-- RIGHT SIDE -->
    <div class="panel">
      <div class="panel-top">
        <img src="logo.png" alt="Cebu Technological University Logo">
        <h2>Campus Access History</h2>
        <p>Log in to view your access logs</p>
      </div>

      <?php if ($notice): ?><div class="msg note"><?= e($notice) ?></div><?php endif; ?>
      <?php if ($error):  ?><div class="msg err"><?= e($error) ?></div><?php endif; ?>

      <form method="post" autocomplete="on">
        <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="login">

        <div class="field">
          <label for="id_number">ID Number</label>
          <div class="with-icon">
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>
            <input type="text" id="id_number" name="id_number" placeholder="Enter your ID number" value="<?= e($_POST['id_number'] ?? '') ?>" autocomplete="username" required autofocus>
          </div>
        </div>

        <div class="field">
          <label for="birthday">Birthday</label>
          <input type="date" id="birthday" name="birthday" autocomplete="bday" max="<?= e(date('Y-m-d')) ?>" required>
        </div>

        <label class="remember" for="remember">
          <input type="checkbox" id="remember" name="remember" value="1">
          Keep me logged in
        </label>

        <button class="submit" type="submit">Log in</button>
      </form>

      <div class="divider"></div>
      <p class="reg-line">Don't have an account? <a href="register.html">Register</a></p>

      <div class="footer">
        Cebu Technological University •
        Campus Access Control System • CACS
      </div>
    </div>

  </div>
</div>

<?php else: ?>
<!-- ========== MY LOGS ========== -->
<div class="container top">
  <div class="wrap">

    <div class="bar">
      <div class="eyebrow">
        <span class="mono"><img src="logo.png" alt="CTU logo"></span>
        <span>Cebu Technological University</span>
        <span class="divider-dot"></span>
        <span class="tagline">My Access Logs</span>
      </div>

      <form method="post">
        <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="logout">
        <button class="out-btn" type="submit">Log out</button>
      </form>
    </div>

    <div class="card">
      <div class="top-row">
        <?php if ($photo): ?><img class="avatar" src="<?= e($photo) ?>" alt=""><?php endif; ?>
        <div class="who">
          <h2><?= e($fullName) ?></h2>
          <div class="meta"><?= e(strtoupper((string)$me['role'])) ?>  •  ID <?= e($myId) ?><?= $info ? '<br>' . e(implode('  •  ', $info)) : '' ?></div>
          <span class="chip <?= $me['status'] === 'IN' ? 'in' : 'out' ?>"><?= $me['status'] === 'IN' ? 'Currently inside' : 'Currently outside' ?></span>
        </div>
      </div>
    </div>

    <div id="annBox"><?= ann_html($announcements, $newCount) ?></div>

    <div class="stats">
      <div class="stat"><b><?= (int)$sum['ins'] ?></b><span>Entries</span></div>
      <div class="stat"><b><?= (int)$sum['outs'] ?></b><span>Exits</span></div>
      <div class="stat"><b><?= (int)$sum['denied'] ?></b><span>Denied</span></div>
      <div class="stat"><b><?= $total ?></b><span>Total records</span></div>
    </div>

    <div class="card">
      <div class="presets">
        <?php foreach ($presets as $label => $p):
          $on = !$all && $from === $p['from'] && $to === $p['to']; ?>
          <a class="pill <?= $on ? 'on' : '' ?>" href="?<?= e(http_build_query($p)) ?>"><?= e($label) ?></a>
        <?php endforeach; ?>
        <a class="pill <?= $all ? 'on' : '' ?>" href="?all=1">All time</a>
      </div>

      <form class="range" method="get">
        <div class="field">
          <label for="from">From</label>
          <input type="date" id="from" name="from" value="<?= e($from) ?>" max="<?= e($today) ?>">
        </div>
        <div class="field">
          <label for="to">To</label>
          <input type="date" id="to" name="to" value="<?= e($to) ?>" max="<?= e($today) ?>">
        </div>
        <button class="btn" type="submit">Apply</button>
        <a class="btn ghost" href="<?= e(strtok($_SERVER['REQUEST_URI'], '?')) ?>">Reset</a>
      </form>
    </div>

    <div class="card">
      <div class="tablewrap">
        <table>
          <thead><tr><th>Date</th><th>Time</th><th>Status</th><th>Activity</th></tr></thead>
          <tbody>
          <?php if (!$rows): ?>
            <tr><td colspan="4" class="empty">No records for this date range.</td></tr>
          <?php else: foreach ($rows as $r):
            $ts = strtotime($r['timestamp']);
            $st = $r['status'];
            if ($st === 'IN')       { $cls = 'in';     $act = 'Entered'; }
            elseif ($st === 'OUT')  { $cls = 'out';    $act = 'Exited'; }
            else                    { $cls = 'denied'; $act = ($r['type'] === 'ENTRY') ? 'Entry not granted' : 'Exit not recorded'; }
          ?>
            <tr>
              <td><?= e(date('D, M j, Y', $ts)) ?></td>
              <td><?= e(date('g:i A', $ts)) ?></td>
              <td><span class="lbadge <?= $cls ?>"><?= e($st) ?></span></td>
              <td><?= e($act) ?></td>
            </tr>
          <?php endforeach; endif; ?>
          </tbody>
        </table>
      </div>

      <?php if ($total > 0): ?>
      <div class="pager">
        <a class="btn ghost <?= $page <= 1 ? 'off' : '' ?>" href="<?= e(pageUrl($page - 1)) ?>">← Newer</a>
        <span>Page <?= $page ?> of <?= $pages ?></span>
        <a class="btn ghost <?= $page >= $pages ? 'off' : '' ?>" href="<?= e(pageUrl($page + 1)) ?>">Older →</a>
      </div>
      <?php endif; ?>
    </div>

  </div>
</div>
<?php endif; ?>

<?php if ($loggedIn): ?>
<script>
// Live announcements: check every 10 seconds (and when the tab comes back), only while the page is visible
(function () {
  var box = document.getElementById('annBox');
  if (!box) return;
  var last = box.innerHTML.trim();
  var busy = false;

  function openKeys() {
    var k = [];
    box.querySelectorAll('details[open]').forEach(function (d) { k.push(d.getAttribute('data-key')); });
    return k;
  }

  function refresh() {
    if (busy || document.hidden) return;
    busy = true;
    fetch('my_logs.php?ann=1&_=' + Date.now(), { cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) {
        if (r.status === 401) { location.reload(); return null; }   // session ended: show the login page
        return r.json();
      })
      .then(function (d) {
        if (!d || !d.ok) return;
        var html = (d.html || '').trim();
        if (html === last) return;
        var open = openKeys();                                      // keep what the member had opened
        box.innerHTML = d.html;
        last = html;
        box.querySelectorAll('details').forEach(function (x) {
          if (open.indexOf(x.getAttribute('data-key')) !== -1) x.open = true;
        });
      })
      .catch(function () {})
      .then(function () { busy = false; });
  }

  setInterval(refresh, 10000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) refresh(); });
})();
</script>
<?php endif; ?>
</body>
</html>