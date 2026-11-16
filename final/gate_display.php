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

// ---- Latest scan (saved by scanner_hw.php into gate_latest.json) ----
if (isset($_GET['poll'])) {
  session_write_close();
  header('Content-Type: application/json; charset=utf-8');
  header("Cache-Control: no-cache, no-store, must-revalidate");

  $file = __DIR__ . '/gate_latest.json';
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gate Display</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
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
body.denied { background: #991b1b; }
body.duplicate { background: #92400e; }

#idle { font-size: clamp(28px, 5vw, 56px); font-weight: 600; opacity: .85; }
#idle small { display: block; margin-top: 12px; font-size: clamp(14px, 2vw, 22px); font-weight: 400; opacity: .7; }

#card { display: none; flex-direction: column; align-items: center; gap: 18px; }
#photo {
  width: min(42vh, 60vw); height: min(42vh, 60vw); border-radius: 50%;
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
#alumni {
  display: none; padding: 6px 22px; border-radius: 999px; font-weight: 800; letter-spacing: .08em;
  color: #5b3b00; background: linear-gradient(135deg, #f7d774, #d4a017); border: 1px solid #b7791f;
  font-size: clamp(14px, 2vw, 24px);
}
#msg { font-size: clamp(16px, 2.4vw, 28px); opacity: .9; }
#conn { position: fixed; bottom: 10px; right: 14px; font-size: 12px; opacity: .6; }
</style>
</head>
<body>

<!-- Put your CTU logo next to this file as ctu_logo.png; until then lego.png is used -->
<div class="topbar">
  <img src="<?= is_file(__DIR__ . '/ctu_logo.png') ? 'ctu_logo.png' : 'lego.png' ?>" alt="Logo">
  <div class="school"><b>Cebu Technological University</b><span>Main Campus</span></div>
</div>

<div id="idle">Please scan your ID<small>Hold your badge in front of the scanner</small></div>

<div id="card">
  <img id="photo" alt="">
  <div id="alumni">ALUMNI</div>
  <div id="name"></div>
  <div id="meta"></div>
  <div id="badge"></div>
  <div id="msg"></div>
</div>

<div id="conn"></div>

<script>
const POLL_MS = 1000;
const PLACEHOLDER = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#8a9bb5" stroke-width="1.5">' +
  '<circle cx="12" cy="9" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>');
const LABELS = { ENTRY: 'IN', EXIT: 'OUT', DUPLICATE: 'ALREADY SCANNED', DENIED: 'ACCESS DENIED' };

const idle = document.getElementById('idle'), card = document.getElementById('card');
const photo = document.getElementById('photo'), nameEl = document.getElementById('name');
const metaEl = document.getElementById('meta'), badge = document.getElementById('badge');
const msgEl = document.getElementById('msg'), alumni = document.getElementById('alumni');
const connEl = document.getElementById('conn');
let lastSeq = '', showing = false, polling = false;

function showIdle() {
  showing = false;
  document.body.className = '';
  card.style.display = 'none';
  idle.style.display = 'block';
}

function show(d) {
  showing = true;
  document.body.className = (d.result || 'DENIED').toLowerCase();
  idle.style.display = 'none';
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
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    const res = await fetch('gate_display.php?poll=1&since=' + encodeURIComponent(lastSeq) + '&_=' + Date.now(), {
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