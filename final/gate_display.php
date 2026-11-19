<?php
session_start();
include 'db.php';
include_once 'auth.php';

// Same login check as the scanner, so the public can't open this page directly
if (auth_role() !== 'personnel') {
  if (isset($_GET['poll'])) {
    http_response_code(401);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Session expired']);
  } else {
    header("Location: login.php");
  }
  exit;
}

// Which gate this screen shows: ?gate=in (entrance) or ?gate=out (exit). Default: in.
$gate = strtolower($_GET['gate'] ?? 'in') === 'out' ? 'out' : 'in';

// ---- Latest scan for this gate (saved by scanner_hw.php) ----
if (isset($_GET['poll'])) {
  session_write_close();
  header('Content-Type: application/json; charset=utf-8');
  header("Cache-Control: no-cache, no-store, must-revalidate");

  $file = __DIR__ . '/gate_latest_' . $gate . '.json';
  $d = is_file($file) ? json_decode((string)@file_get_contents($file), true) : null;
  if (!is_array($d) || !isset($d['seq'])) { echo json_encode(['empty' => true]); exit; }

  $age = max(0, time() - (int)($d['time'] ?? 0));
  if (($_GET['since'] ?? '') === (string)$d['seq']) {
    // Same scan as before: skip sending the photo again
    echo json_encode(['unchanged' => true, 'age' => $age]);
    exit;
  }
  $d['age'] = $age;
  echo json_encode($d, JSON_UNESCAPED_UNICODE);
  exit;
}

header("Cache-Control: no-cache, no-store, must-revalidate");
$gateTitle = $gate === 'out' ? 'EXIT GATE' : 'ENTRANCE GATE';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gate Display · <?= $gateTitle ?></title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  height: 100vh; overflow: hidden; display: flex; align-items: center; justify-content: center;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #142c4b; color: #fff; text-align: center; padding: 130px 32px 32px;
  transition: background .2s;
}
body.entry, body.exit { background: #142c4b; }

/* Frame border around the whole screen */
body::after {
  content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 20;
  border: 6px solid #f0b429;
}

/* Header bar with the logo and campus name */
.topbar {
  position: fixed; top: 0; left: 0; right: 0; z-index: 10;
  display: flex; align-items: center; justify-content: center; gap: 22px;
  padding: 18px 24px; background: #0e2036; border-bottom: 4px solid #f0b429;
}
.topbar img { width: clamp(52px, 8vh, 84px); height: clamp(52px, 8vh, 84px); border-radius: 50%; object-fit: cover; }
.topbar .school { text-align: left; line-height: 1.2; }
.topbar .school b { display: block; font-size: clamp(18px, 3.2vh, 34px); font-weight: 800; letter-spacing: .02em; }
.topbar .school span { font-size: clamp(13px, 2.2vh, 24px); opacity: .85; }
.topbar .gate-name { font-weight: 800; color: #f0b429; letter-spacing: .06em; }

/* Live clock in the header */
.clock {
  position: absolute; right: 28px; top: 50%; transform: translateY(-50%);
  text-align: right; line-height: 1.15;
}
.clock #clk-time { display: block; font-size: clamp(22px, 4vh, 44px); font-weight: 800; font-variant-numeric: tabular-nums; }
.clock #clk-date { display: block; font-size: clamp(12px, 2vh, 22px); opacity: .85; }
@media (max-width: 700px) { .clock { display: none; } }

body.denied { background: #991b1b; }
body.duplicate { background: #92400e; }

#idle { font-size: clamp(28px, 5vw, 56px); font-weight: 600; opacity: .85; }
#idle small { display: block; margin-top: 12px; font-size: clamp(14px, 2vw, 22px); font-weight: 400; opacity: .7; }

#card { display: none; flex-direction: column; align-items: center; gap: 18px; }
#photo {
  width: min(30vh, 45vw); height: min(30vh, 45vw); border-radius: 50%;
  object-fit: cover; border: 6px solid #fff; background: #dce4ef;
  box-shadow: 0 8px 40px rgba(0,0,0,.35);
}
#name { font-size: clamp(32px, 6vw, 72px); font-weight: 800; line-height: 1.1; }
#meta { font-size: clamp(16px, 2.6vw, 30px); opacity: .9; white-space: pre-line; line-height: 1.5; }
#badge {
  padding: 10px 34px; border-radius: 999px; background: rgba(255,255,255,.22);
  font-size: clamp(22px, 3.6vw, 44px); font-weight: 800; letter-spacing: .06em;
}
body.entry #badge { background: #16a34a; color: #fff; }
body.exit  #badge { background: rgba(186, 215, 255, 0.6); color: #000; }

/* Time of the scan shown on the card */
#scantime { font-size: clamp(14px, 2.2vw, 26px); opacity: .85; font-variant-numeric: tabular-nums; }

#alumni {
  display: none; padding: 6px 22px; border-radius: 999px; font-weight: 800; letter-spacing: .08em;
  color: #5b3b00; background: linear-gradient(135deg, #f7d774, #d4a017); border: 1px solid #b7791f;
  font-size: clamp(14px, 2vw, 24px);
}
#msg { font-size: clamp(16px, 2.4vw, 28px); opacity: .9; }
#conn { position: fixed; bottom: 10px; right: 14px; font-size: 12px; opacity: .6; }

/* ---- Group visitor card ---- */
#groupCard {
  display: none; flex-direction: column; gap: 16px;
  width: min(94vw, 1200px); max-height: calc(100vh - 170px);
  text-align: left;
}
#groupCard .g-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; }
#groupCard .g-right { text-align: right; flex-shrink: 0; }
#groupCard .g-label { font-size: clamp(12px, 1.8vw, 20px); font-weight: 700; opacity: .8; letter-spacing: .06em; }
#groupCard .g-name { font-size: clamp(26px, 4.4vw, 56px); font-weight: 800; line-height: 1.1; margin-top: 6px; }
#groupCard .g-sub { font-size: clamp(14px, 2vw, 24px); opacity: .85; margin-top: 8px; }
#groupCard .g-badge {
  display: inline-block; padding: 10px 34px; border-radius: 999px; background: rgba(255,255,255,.22);
  font-size: clamp(22px, 3.6vw, 44px); font-weight: 800; letter-spacing: .06em;
}
body.entry .g-badge { background: #16a34a; color: #fff; }
body.exit  .g-badge { background: rgba(186, 215, 255, 0.6); color: #000; }
#groupCard .g-time { font-size: clamp(14px, 2vw, 22px); opacity: .85; margin-top: 8px; font-variant-numeric: tabular-nums; }
#groupCard .g-leader {
  display: flex; align-items: baseline; gap: 16px; padding: 12px 22px; border-radius: 14px;
  background: rgba(255,255,255,.12); border: 1px solid rgba(240,180,41,.6);
}
#groupCard .g-tag { font-size: clamp(12px, 1.6vw, 18px); font-weight: 700; color: #f0b429; letter-spacing: .06em; }
#groupCard .g-who { font-size: clamp(18px, 2.8vw, 34px); font-weight: 700; }
#groupCard .g-members {
  flex: 1 1 auto; min-height: 0; overflow: hidden;
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); grid-auto-rows: max-content;
  align-content: start; gap: 8px;
}
#groupCard .g-member {
  padding: 8px 12px; border-radius: 10px; background: rgba(255,255,255,.12);
  font-size: clamp(12px, 1.7vh, 20px); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
#groupCard .g-members.dense .g-member { font-size: clamp(11px, 1.3vh, 16px); padding: 6px 8px; }
#groupCard .g-msg { font-size: clamp(16px, 2.4vw, 28px); opacity: .9; text-align: right; }
</style>
</head>
<body>

<!-- Put your CTU logo next to this file as ctu_logo.png; until then lego.png is used -->
<div class="topbar">
  <img src="<?= is_file(__DIR__ . '/ctu_logo.png') ? 'ctu_logo.png' : 'lego.png' ?>" alt="Logo">
  <div class="school"><b>Cebu Technological University</b><span>Main Campus · <span class="gate-name"><?= $gateTitle ?></span></span></div>
  <div class="clock"><span id="clk-time"></span><span id="clk-date"></span></div>
</div>

<div id="idle">Please scan your ID<small>Hold your badge in front of the scanner</small></div>

<div id="card">
  <img id="photo" alt="">
  <div id="alumni">ALUMNI</div>
  <div id="name"></div>
  <div id="meta"></div>
  <div id="badge"></div>
  <div id="scantime"></div>
  <div id="msg"></div>
</div>

<div id="groupCard"></div>

<div id="conn"></div>

<script>
const POLL_MS = 1000;
const GATE = '<?= $gate ?>';          // 'in' or 'out' from the address (?gate=)
const PLACEHOLDER = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#8a9bb5" stroke-width="1.5">' +
  '<circle cx="12" cy="9" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>');
const LABELS = { ENTRY: 'IN', EXIT: 'OUT', DUPLICATE: 'ALREADY SCANNED', DENIED: 'ACCESS DENIED' };

const idle = document.getElementById('idle'), card = document.getElementById('card');
const photo = document.getElementById('photo'), nameEl = document.getElementById('name');
const metaEl = document.getElementById('meta'), badge = document.getElementById('badge');
const msgEl = document.getElementById('msg'), alumni = document.getElementById('alumni');
const connEl = document.getElementById('conn');
const groupCard = document.getElementById('groupCard');
let lastSeq = '', showing = false, polling = false;

// ---- Clock and date (fixed to Philippine time, independent of the PC's timezone) ----
const TZ = 'Asia/Manila';
const scantimeEl = document.getElementById('scantime');
const clkTime = document.getElementById('clk-time'), clkDate = document.getElementById('clk-date');

function tickClock() {
  const now = new Date();
  clkTime.textContent = now.toLocaleTimeString('en-US', { timeZone: TZ, hour: 'numeric', minute: '2-digit', second: '2-digit' });
  clkDate.textContent = now.toLocaleDateString('en-US', { timeZone: TZ, weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
}
tickClock();
setInterval(tickClock, 1000);

// Date and time of a scan (Unix timestamp in seconds), in Philippine time
function scanTimeText(unixSeconds) {
  const t = new Date(unixSeconds * 1000);
  return t.toLocaleDateString('en-US', { timeZone: TZ, year: 'numeric', month: 'short', day: 'numeric' }) + '  •  ' +
         t.toLocaleTimeString('en-US', { timeZone: TZ, hour: 'numeric', minute: '2-digit', second: '2-digit' });
}

function showIdle() {
  showing = false;
  document.body.className = '';
  card.style.display = 'none';
  groupCard.style.display = 'none';
  idle.style.display = 'block';
}

// Group visitor: one card with the group name, the leader and every member
function showGroup(d) {
  const g = d.group;
  const add = (parent, tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    parent.appendChild(e);
    return e;
  };

  groupCard.textContent = '';

  const head = add(groupCard, 'div', 'g-head');
  const left = add(head, 'div', '');
  add(left, 'div', 'g-label', 'GROUP VISITOR · ' + g.size + ' PEOPLE');
  add(left, 'div', 'g-name', g.name);
  const sub = [];
  if (g.purpose)     sub.push('Purpose: ' + g.purpose);
  if (g.destination) sub.push('Destination: ' + g.destination);
  if (sub.length) add(left, 'div', 'g-sub', sub.join('  ·  '));

  const right = add(head, 'div', 'g-right');
  add(right, 'div', 'g-badge', LABELS[d.result] || 'ACCESS DENIED');
  if (d.time) add(right, 'div', 'g-time', scanTimeText(d.time));

  const leaderRow = add(groupCard, 'div', 'g-leader');
  add(leaderRow, 'span', 'g-tag', 'LEADER');
  add(leaderRow, 'span', 'g-who', g.leader);

  add(groupCard, 'div', 'g-label', 'MEMBERS (' + g.members.length + ')');
  const n = g.members.length;
  const list = add(groupCard, 'div', 'g-members');
  // Keep everything on one screen: more columns and smaller text for bigger groups
  const cols = n <= 8 ? 4 : n <= 18 ? 6 : 8;
  list.style.gridTemplateColumns = 'repeat(' + cols + ', minmax(0, 1fr))';
  if (n > 8) list.classList.add('dense');
  g.members.forEach(function (m, i) {
    add(list, 'div', 'g-member', (i + 2) + '. ' + m);
  });

  add(groupCard, 'div', 'g-msg', d.message || '');

  card.style.display = 'none';
  groupCard.style.display = 'flex';
}

function show(d) {
  showing = true;
  document.body.className = (d.result || 'DENIED').toLowerCase();
  idle.style.display = 'none';

  if (d.group) {
    showGroup(d);
    return;
  }

  groupCard.style.display = 'none';
  card.style.display = 'flex';

  photo.onerror = () => { photo.src = PLACEHOLDER; };
  photo.src = d.photo || PLACEHOLDER;
  photo.style.display = d.name ? 'block' : 'none';
  nameEl.textContent = d.name || '';
  metaEl.textContent = (d.role ? d.role.toUpperCase() : '') +
    (d.info && d.info.length ? '\n' + d.info.join('  •  ') : '');
  alumni.style.display = d.alumni ? 'inline-block' : 'none';
  badge.textContent = LABELS[d.result] || 'ACCESS DENIED';
  msgEl.textContent = d.message || '';

  // Date and time the scan was recorded (d.time is a Unix timestamp in seconds)
  scantimeEl.textContent = d.time ? scanTimeText(d.time) : '';
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    const res = await fetch('gate_display.php?poll=1&gate=' + GATE + '&since=' + encodeURIComponent(lastSeq) + '&_=' + Date.now(), {
      cache: 'no-store', credentials: 'same-origin'
    });
    if (res.status === 401) { connEl.textContent = 'Session expired. Reload and log in again.'; return; }
    const d = await res.json();
    connEl.textContent = '';

    // Nothing new: leave the current scan on screen until the next one arrives
    if (d.empty || d.unchanged) return;
    lastSeq = String(d.seq);
    show(d);
  } catch (e) {
    connEl.textContent = 'Connection lost. Retrying...';
  } finally {
    polling = false;
  }
}

poll();
setInterval(poll, POLL_MS);

// Click once for full screen (browsers require a click)
document.addEventListener('click', () => {
  if (!document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => {});
});
</script>
</body>
</html>