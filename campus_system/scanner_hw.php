<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Scanner</title>

  <style>
  * {
    box-sizing: border-box;
  }

  body {
    margin: 0;
    height: 100vh;
    overflow: hidden;

    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;

    background: #fafbfd;

    display: flex;
    justify-content: center;
    align-items: center;
  }

  .container {
    width: 360px;
    padding: 30px;

    background: #ffffff;

    border-radius: 18px;
    border: 1px solid #dce4ef;
    box-shadow: 0 1px 3px rgba(22,58,94,0.05);

    text-align: center;
    color: #16233d;
  }

  h2 {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 6px;
    color: #16233d;
  }

  .subtitle {
    font-size: 12px;
    color: #8a9bb5;
    margin-bottom: 20px;
  }

  /* Big status circle standing in for the camera preview */
  #readerVisual {
    width: 100%;
    aspect-ratio: 1 / 1;
    max-height: 220px;
    border-radius: 14px;
    border: 2px dashed #c7d7ec;
    background: #f4f7fb;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    transition: all 0.15s ease;
  }

  #readerVisual .icon {
    font-size: 40px;
    opacity: 0.6;
  }

  #readerVisual .status-text {
    font-size: 13px;
    color: #6b7a94;
    font-weight: 600;
  }

  #readerVisual.scanning {
    border-color: #1c3a5e;
    background: #eef3fa;
  }

  #readerVisual.success {
    border-color: #16a34a;
    background: #e8f8ef;
  }

  #readerVisual.error {
    border-color: #dc2626;
    background: #fdeaea;
  }

  #result {
    margin-top: 15px;
    font-size: 14px;
    color: #6b7a94;
    min-height: 20px;
  }

  /* Hidden always-focused input that the hardware scanner "types" into */
  #scanInput {
    position: absolute;
    opacity: 0;
    pointer-events: none;
    width: 1px;
    height: 1px;
  }

  .back {
    margin-top: 15px;
  }

  .back a {
    text-decoration: none;
    font-size: 13px;
    color: #8a9bb5;
  }

  .back a:hover {
    color: #1c3a5e;
  }
  </style>
</head>

<body>

<div class="container">

  <h2>Scan QR / Barcode</h2>
  <div class="subtitle">Hardware scanner mode</div>

  <div id="readerVisual">
    <div class="icon">📷</div>
    <div class="status-text" id="statusText">Ready — point scanner at badge</div>
  </div>

  <p id="result">Waiting for scan...</p>

  <input type="text" id="scanInput" autocomplete="off">

  <div class="back">
    <a href="dashboard.php">← Back to Dashboard</a>
  </div>

</div>

<!-- SOUNDS -->
<audio id="successSound" src="https://actions.google.com/sounds/v1/cartoon/clang_and_wobble.ogg"></audio>
<audio id="errorSound" src="https://actions.google.com/sounds/v1/alarms/beep_short.ogg"></audio>

<script>
const scanInput   = document.getElementById('scanInput');
const readerVisual = document.getElementById('readerVisual');
const statusText  = document.getElementById('statusText');
const resultText  = document.getElementById('result');

let buffer = '';
let lastKeyTime = 0;
let scanTimer = null;
let busy = false; // true while a scan is being verified, blocks new scans

// A hardware scanner fires keystrokes far faster than a human can type.
// If the gap between keys is under this threshold, treat it as scanner input.
const FAST_KEY_THRESHOLD_MS = 40;
// If no new keys arrive for this long after the buffer starts, flush it.
const FLUSH_IDLE_MS = 80;

function playSuccess() {
  document.getElementById('successSound').play();
  if (navigator.vibrate) navigator.vibrate(200);
}

function playError() {
  document.getElementById('errorSound').play();
  if (navigator.vibrate) navigator.vibrate([100, 50, 100]);
}

function setVisual(state, message) {
  readerVisual.classList.remove('scanning', 'success', 'error');
  if (state) readerVisual.classList.add(state);
  if (message) statusText.textContent = message;
}

function refocus() {
  scanInput.value = '';
  scanInput.focus();
}

function isUserBarcode(code) {
  return /^[0-9]{1,8}$/.test(code);
}

function fetchVerify(code) {
  busy = true;
  setVisual('scanning', 'Verifying...');
  resultText.innerText = 'Verifying ' + code + '...';

  fetch('face_verify.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'code=' + encodeURIComponent(code)
  })
  .then(res => res.text())
  .then(data => {
    document.open();
    document.write(data);
    document.close();
  })
  .catch(() => {
    playError();
    setVisual('error', 'Error — try again');
    resultText.innerHTML = '❌ Error processing scan';
    busy = false;
    refocus();
  });
}

function handleScan(code) {
  if (busy || !code) return;

  const normalized = code.trim();
  if (!normalized) return;

  playSuccess();
  setVisual('success', 'Scan received');
  resultText.innerHTML = 'Detected: <strong>' + normalized + '</strong>' +
    '<br><span style="font-size:11px;color:#a3b3cc;">raw length: ' + normalized.length +
    ' | chars: [' + Array.from(normalized).map(c => c.charCodeAt(0)).join(',') + ']</span>';

  // Ask the server what this code actually belongs to before ever
  // offering face verification — visitors never have face data on file,
  // so they should never see the face-verification prompt.
  fetch('check_code_type.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'code=' + encodeURIComponent(normalized)
  })
  .then(res => res.json())
  .then(data => {
    if (data.type === 'user') {
      const useFace = confirm('Use face verification?');
      if (useFace) {
        window.location.href = 'face_verify.html?code=' + encodeURIComponent(normalized);
        return;
      }
    }
    // Visitor, or unknown/not found — skip straight to verification,
    // no face-verification prompt shown.
    fetchVerify(normalized);
  })
  .catch(() => {
    // If the lookup itself fails, fall back to verifying directly
    // rather than blocking the scan entirely.
    fetchVerify(normalized);
  });
}

scanInput.addEventListener('keydown', (e) => {
  if (busy) { e.preventDefault(); return; }

  const now = Date.now();
  const gap = now - lastKeyTime;
  lastKeyTime = now;

  if (e.key === 'Enter') {
    e.preventDefault();
    if (scanTimer) clearTimeout(scanTimer);
    const code = buffer;
    buffer = '';
    scanInput.value = '';
    handleScan(code);
    return;
  }

  // Only accumulate normal printable characters
  if (e.key.length === 1) {
    buffer += e.key;
  } else if (e.key !== 'Shift' && e.key !== 'Control' && e.key !== 'Alt') {
    // A non-printable key arrived mid-scan (e.g. NumLock off sending Insert/Home/arrows
    // instead of digits). Show it so we can diagnose keyboard layout issues.
    console.warn('Ignored non-printable key during scan:', e.key);
    resultText.innerHTML = '⚠️ Unexpected key: <strong>' + e.key + '</strong> (check NumLock / keyboard layout on the scanner)';
  }

  // Fallback flush: some scanners don't send a trailing Enter.
  // If keys stop arriving briefly after a fast burst, treat it as done.
  if (scanTimer) clearTimeout(scanTimer);
  scanTimer = setTimeout(() => {
    if (buffer.length > 0) {
      const code = buffer;
      buffer = '';
      scanInput.value = '';
      handleScan(code);
    }
  }, FLUSH_IDLE_MS);
});

// Keep the hidden input focused at all times so keystrokes are always captured
document.addEventListener('click', refocus);
window.addEventListener('load', refocus);
setInterval(() => {
  if (!busy && document.activeElement !== scanInput) refocus();
}, 500);
</script>

</body>
</html>