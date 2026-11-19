<?php
session_start();
include 'db.php';
include_once 'auth.php';

// Patrol check page: security personnel only
require_auth($conn, ['personnel']);

header("Cache-Control: no-cache, no-store, must-revalidate");
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Patrol Check</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 16px; min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #fafbfd; color: #16233d;
    }
    .wrap { max-width: 480px; margin: 0 auto; }
    .card {
      background: #fff; border: 1px solid #dce4ef; border-radius: 16px;
      padding: 16px; margin-bottom: 14px; text-align: center;
      box-shadow: 0 1px 3px rgba(22,58,94,0.05);
    }
    h3 { margin: 0 0 4px; font-size: 18px; }
    .subtitle { font-size: 12px; color: #8a9bb5; margin-bottom: 12px; }
    #reader { width: 100%; border-radius: 12px; overflow: hidden; }

    #banner {
      display: none; padding: 12px; margin-bottom: 10px; border-radius: 10px;
      color: #fff; background: #b91c1c; font-weight: 800; letter-spacing: .03em;
      animation: pulse 0.8s ease-in-out infinite alternate;
    }
    @keyframes pulse { from { opacity: 1; } to { opacity: .65; } }

    #photo {
      display: none; width: 140px; height: 140px; border-radius: 50%;
      object-fit: cover; margin: 8px auto; border: 3px solid #fff;
      box-shadow: 0 2px 10px rgba(22,35,61,0.15); background: #dce4ef;
    }
    #name { font-size: 20px; font-weight: 700; }
    #meta { font-size: 13px; color: #6b7a94; white-space: pre-line; line-height: 1.5; margin: 4px 0 10px; }
    #alumni {
      display: none; margin: 0 auto 8px; padding: 4px 14px; border-radius: 999px; width: fit-content;
      font-size: 12px; font-weight: 800; letter-spacing: .08em; color: #5b3b00;
      background: linear-gradient(135deg, #f7d774, #d4a017); border: 1px solid #b7791f;
    }
    #badge {
      display: none; padding: 6px 16px; border-radius: 999px;
      color: #fff; font-weight: 700; font-size: 14px; letter-spacing: .04em;
    }
    .inside #badge     { background: #16a34a; }
    .not_inside #badge { background: #dc2626; }
    .denied #badge     { background: #dc2626; }
    #msg { margin-top: 10px; font-weight: 600; font-size: 14px; white-space: pre-line; color: #3c4a63; }

    #verifyBtn {
      display: none; margin-top: 12px; padding: 10px 18px;
      border: 1px solid #c7d7ec; border-radius: 10px; background: #fff;
      font: 600 14px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; cursor: pointer;
    }
    .back a {
      display: block; padding: 12px 16px; background: #fff; text-align: center;
      border: 1px solid #dce4ef; border-radius: 12px; text-decoration: none;
      font-size: 14px; font-weight: 600; color: #16233d;
    }
  </style>
</head>
<body>
<div class="wrap">

  <div class="card">
    <h3>Patrol Check</h3>
    <div class="subtitle">Read-only: scanning here never changes IN/OUT status</div>
    <div id="reader"></div>
  </div>

  <div class="card" id="result">
    <div id="banner" role="alert">REPEATED ACCESS DENIAL — PLEASE INVESTIGATE</div>
    <img id="photo" alt="">
    <div id="alumni">ALUMNI</div>
    <div id="name">Scan an ID</div>
    <div id="meta"></div>
    <div id="badge"></div>
    <div id="msg">Point the camera at the barcode or QR code</div>
    <button id="verifyBtn" type="button">Verify face</button>
  </div>

  <div class="back"><a href="dashboard.php">Back to Dashboard

  </a></div>
</div>


<script src="html5-qrcode.min.js"></script>
<script>
  // Fallback: if the local copy is missing, load a pinned copy from unpkg
  if (typeof Html5Qrcode === 'undefined') {
    document.write('<script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"><\/script>');
  }
</script>
<script>
const $ = id => document.getElementById(id);
const PLACEHOLDER = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#8a9bb5" stroke-width="1.5">' +
  '<circle cx="12" cy="9" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>');

let lastCode = '', lastTime = 0, busy = false, verifyCode = null;

async function check(code) {
  if (!code) return;
  const now = Date.now();
  if (busy || (code === lastCode && now - lastTime < 4000)) return;   // ignore repeat reads of the same card
  busy = true; lastCode = code; lastTime = now;
  $('msg').textContent = 'Checking...';

  try {
    const r = await fetch('scanner_hw.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=check&code=' + encodeURIComponent(code)
    });
    if (r.status === 401) {                       // session expired
      location.href = 'login.php';
      return;
    }
    show(await r.json());
  } catch (e) {
    show({ result: 'DENIED', message: 'Network error, scan again' });
  } finally {
    busy = false;
  }
}

function show(d) {
  $('result').className = 'card ' + (d.result || 'denied').toLowerCase();
  $('banner').style.display = d.suspicious ? 'block' : 'none';
  $('alumni').style.display = d.alumni ? 'block' : 'none';

  $('name').textContent = d.name || (d.id ? 'Code: ' + d.id : 'Unknown');
  $('meta').textContent = (d.role ? d.role.toUpperCase() : '') + (d.id && d.name ? '  •  ID ' + d.id : '') +
    (d.info && d.info.length ? '\n' + d.info.join('  •  ') : '');

  if (d.name) {
    const p = $('photo');
    p.onerror = () => { p.src = PLACEHOLDER; };
    p.src = d.photo || PLACEHOLDER;
    p.style.display = 'block';
  } else {
    $('photo').style.display = 'none';
  }

  $('badge').textContent = ({ INSIDE: 'INSIDE', NOT_INSIDE: 'NOT INSIDE' })[d.result] || 'DENIED';
  $('badge').style.display = 'inline-block';
  $('msg').textContent = d.message || '';

  verifyCode = d.id || null;
  $('verifyBtn').style.display = (d.has_face && verifyCode) ? 'inline-block' : 'none';

  if (navigator.vibrate) navigator.vibrate(d.result === 'INSIDE' ? 200 : [100, 50, 100]);
}

// patrol=1 tells face_verify.html / scanner_hw.php this is a roving check
$('verifyBtn').onclick = () => {
  if (verifyCode) location.href = 'face_verify.html?code=' + encodeURIComponent(verifyCode) + '&patrol=1';
};

// Start the rear camera
if (typeof Html5Qrcode === 'undefined') {
  $('msg').textContent = 'Camera library could not load. Check the internet connection or upload html5-qrcode.min.js.';
  throw new Error('Html5Qrcode missing');
}
const scanner = new Html5Qrcode('reader');
scanner.start(
  { facingMode: 'environment' },
  { fps: 10, qrbox: { width: 260, height: 160 } },
  text => check(text.trim()),
  () => {}                                   // ignore per-frame "not found" noise
).catch(err => {
  $('msg').textContent = 'Camera error: ' + err + '. Make sure the site uses HTTPS and camera access is allowed.';
});
</script>
</body>
</html>