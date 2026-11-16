/* liveness.js - face-following oval, challenge-response liveness, basic spoof checks
   Requires face-api.js (tinyFaceDetector + faceLandmark68Net loaded).
   Updated for phones: smaller camera box, lighter detector, blink tuned for slower frame rates.
   Oval overlay now hugs the face using the landmarks (jaw, chin, eyebrows + forehead room)
   and matches the displayed (object-fit: cover) video. */
(function () {
  // ---- Phone detection (re-checked when the screen size changes) ----
  const mq = window.matchMedia('(max-width: 800px)');
  const isSmall = () => mq.matches;

  // ---- Tunable settings ----
  const CFG = {
    challengeCount: 2,        // how many random challenges
    challengeTimeoutMs: 10000,// time allowed per challenge (a little longer for slower phones)
    turnLeft: 0.65,           // nose ratio thresholds (0.5 = facing camera)
    turnRight: 0.35,
    mouthOpen: 0.35,
    blinkDrop: 0.9,           // blink = eye openness drops 10% from recent peak
    maxPitchShift: 0.07,      // head up/down movement allowed during a blink (nod filter)
    minSharpness: 25,         // Laplacian variance; below = blurry print/replay (tune!)
    minFaceRatio: 0.18,       // face width / video width, must be close enough
    fitPad: 1.08,             // oval size vs. the face (1.0 = tight, 1.15 = roomier)
    foreheadExtra: 0.45       // extra room above the eyebrows for the forehead (0.3 to 0.6)
  };

  console.log('liveness.js loaded: landmark-fitted oval v4');

  let video, statusEl, canvas, ctx, promptEl, wrap;
  let latest = null, multiFace = false, mode = 'idle'; // idle | active | pass | fail
  let oval = null; // smoothed {cx, cy, rx, ry}

  // Smaller input = faster on phones. Must be a multiple of 32.
  const opts = () => new faceapi.TinyFaceDetectorOptions({
    inputSize: isSmall() ? 160 : 192,
    scoreThreshold: 0.5
  });
  const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function ear(p) { return (dist(p[1], p[5]) + dist(p[2], p[4])) / (2 * dist(p[0], p[3])); }
  function eyesEAR(pts) { return (ear(pts.slice(36, 42)) + ear(pts.slice(42, 48))) / 2; }
  function yawRatio(pts) { return (pts[30].x - pts[0].x) / (pts[16].x - pts[0].x); }
  function mouthRatio(pts) { return dist(pts[62], pts[66]) / dist(pts[48], pts[54]); }
  // Head up/down proxy: where the nose tip sits between the eyes and the chin
  function pitchRatio(pts) {
    const eyeY = (pts[36].y + pts[39].y + pts[42].y + pts[45].y) / 4;
    return (pts[30].y - eyeY) / (pts[8].y - eyeY);
  }

  // Camera box size: 80% of the panel on desktop, a compact box on phones
  function applyWrapSize() {
    if (!wrap) return;
    wrap.style.width = isSmall() ? 'min(90%, 240px)' : '80%';
  }

  // ---- Setup: wrap video, add overlay canvas ----
  function init(v, statusElement) {
    video = v; statusEl = statusElement;
    wrap = document.createElement('div');
    wrap.style.cssText = 'position:relative;line-height:0;';
    applyWrapSize();
    video.parentNode.insertBefore(wrap, video);
    wrap.appendChild(video);
    video.style.width = '100%';
    video.setAttribute('playsinline', '');
    video.muted = true;
    video.play().catch(() => {});   // moving the video can pause it on some phones

    if (mq.addEventListener) mq.addEventListener('change', applyWrapSize);

    canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;left:0;top:0;width:100%;height:100%;transform:scaleX(-1);pointer-events:none;';
    wrap.appendChild(canvas);
    ctx = canvas.getContext('2d');

    promptEl = document.createElement('div');
    promptEl.style.cssText = 'position:absolute;left:8px;right:8px;bottom:8px;padding:6px 10px;border-radius:8px;' +
      'background:rgba(22,35,61,.8);color:#fff;font:600 13px sans-serif;text-align:center;line-height:1.4;display:none;';
    wrap.appendChild(promptEl);

    trackLoop();
  }

  function setPrompt(t) {
    promptEl.style.display = t ? 'block' : 'none';
    promptEl.textContent = t || '';
  }

  // ---- Continuous tracking + drawing the oval ----
  async function trackLoop() {
    try {
      if (video.videoWidth && !video.paused) {
        const all = await faceapi.detectAllFaces(video, opts()).withFaceLandmarks();
        multiFace = all.length > 1;
        latest = all.length
          ? all.reduce((a, b) => (a.detection.box.area > b.detection.box.area ? a : b))
          : null;
        draw();
      }
    } catch (e) { console.error(e); }
    requestAnimationFrame(trackLoop);
  }

  function draw() {
    // Size the canvas to the box that is actually displayed, so nothing gets stretched
    const W = wrap.clientWidth, H = wrap.clientHeight;
    if (!W || !H) return;
    if (canvas.width !== W || canvas.height !== H) { canvas.width = W; canvas.height = H; }
    ctx.clearRect(0, 0, W, H);
    if (!latest) { oval = null; return; }

    // Map video pixels to the displayed box the same way object-fit: cover does
    const vw = video.videoWidth, vh = video.videoHeight;
    const s = Math.max(W / vw, H / vh);
    const ox = (W - vw * s) / 2, oy = (H - vh * s) / 2;

    // Oval fitted to the landmarks: jaw width, chin, eyebrows + forehead room
    const pts = latest.landmarks.positions;
    const jaw = pts.slice(0, 17), brows = pts.slice(17, 27);
    const left = Math.min(...jaw.map(p => p.x));
    const right = Math.max(...jaw.map(p => p.x));
    const chinY = pts[8].y;
    const browY = Math.min(...brows.map(p => p.y));
    const topY = browY - (chinY - browY) * CFG.foreheadExtra;
    const t = {
      cx: ox + ((left + right) / 2) * s,
      cy: oy + ((topY + chinY) / 2) * s,
      rx: ((right - left) / 2) * s * CFG.fitPad,
      ry: ((chinY - topY) / 2) * s * CFG.fitPad
    };
    oval = oval ? {
      cx: oval.cx + (t.cx - oval.cx) * 0.4,
      cy: oval.cy + (t.cy - oval.cy) * 0.4,
      rx: oval.rx + (t.rx - oval.rx) * 0.4,
      ry: oval.ry + (t.ry - oval.ry) * 0.4
    } : t;

    const color = { idle: '#4ade80', active: '#f59e0b', pass: '#16a34a', fail: '#dc2626' }[mode];
    ctx.beginPath();
    ctx.ellipse(oval.cx, oval.cy, oval.rx, oval.ry, 0, 0, Math.PI * 2);
    ctx.lineWidth = 7; ctx.strokeStyle = '#ffffff'; ctx.stroke();   // white outline for visibility
    ctx.lineWidth = 4; ctx.strokeStyle = color; ctx.stroke();
  }

  // ---- Spoof heuristic: sharpness (blurry print / low-quality replay) ----
  function sharpness(b) {
    const c = document.createElement('canvas'); c.width = c.height = 64;
    const x = c.getContext('2d', { willReadFrequently: true });
    x.drawImage(video, b.x, b.y, b.width, b.height, 0, 0, 64, 64);
    const d = x.getImageData(0, 0, 64, 64).data, g = [];
    for (let i = 0; i < d.length; i += 4) g.push(0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2]);
    let sum = 0, sq = 0, n = 0;
    for (let j = 1; j < 63; j++) for (let i = 1; i < 63; i++) {
      const k = j * 64 + i;
      const l = g[k - 1] + g[k + 1] + g[k - 64] + g[k + 64] - 4 * g[k];
      sum += l; sq += l * l; n++;
    }
    return sq / n - (sum / n) ** 2;
  }

  // ---- Challenges ----
  const CHALLENGES = {
    left: { text: 'Turn your head to your LEFT' },
    right: { text: 'Turn your head to your RIGHT' },
    mouth: { text: 'Open your mouth' }
  };

  async function waitFor(name) {
    const start = Date.now();
    const hist = [];
    let lastFrame = null;
    let closedAt = 0;

    // Phones run detection at a lower frame rate, so look at fewer frames
    const minHist = isSmall() ? 4 : 6;
    const pitchWindow = isSmall() ? 5 : 8;

    while (Date.now() - start < CFG.challengeTimeoutMs) {
      await sleep(30);
      if (!latest || latest === lastFrame) continue;   // only process new detections
      lastFrame = latest;
      if (multiFace) throw new Error('Multiple faces detected');

      const p = latest.landmarks.positions;

      if (name === 'blink') {
        const e = eyesEAR(p);
        hist.push({ e, pitch: pitchRatio(p) });
        if (hist.length > 30) hist.shift();
        if (hist.length >= minHist) {
          const peak = Math.max(...hist.map(h => h.e));
          const recent = hist.slice(-pitchWindow).map(h => h.pitch);
          const range = Math.max(...recent) - Math.min(...recent);   // how much the head nodded lately
          const steady = range < CFG.maxPitchShift;
          console.log('EAR', e.toFixed(3), 'peak', peak.toFixed(3), 'pitchRange', range.toFixed(3));

          if (!closedAt) {
            if (e < peak * CFG.blinkDrop && steady) closedAt = Date.now();
          } else if (Date.now() - closedAt > 1200) {
            closedAt = 0;                        // stayed low too long: not a blink
          } else if (e > peak * 0.92 && steady) {
            return true;                         // closed then reopened, head steady
          }
        }
      }
      if (name === 'left' && yawRatio(p) > CFG.turnLeft) return true;
      if (name === 'right' && yawRatio(p) < CFG.turnRight) return true;
      if (name === 'mouth' && mouthRatio(p) > CFG.mouthOpen) return true;
    }
    return false;
  }

  async function waitFrontal() {
    for (let i = 0; i < 25; i++) {
      if (latest && Math.abs(yawRatio(latest.landmarks.positions) - 0.5) < 0.12 && eyesEAR(latest.landmarks.positions) > 0.2) return;
      await sleep(60);
    }
  }

  async function run(count) {
    if (!latest) return { ok: false, reason: 'No face detected. Look at the camera.' };
    mode = 'active';
    try {
      if (latest.detection.box.width / video.videoWidth < CFG.minFaceRatio)
        throw new Error('Move closer to the camera');
      if (multiFace) throw new Error('Multiple faces detected');

      const names = Object.keys(CHALLENGES).sort(() => Math.random() - 0.5).slice(0, count || CFG.challengeCount);
      const sharpSamples = [];

      for (const n of names) {
        setPrompt(CHALLENGES[n].text);
        statusEl.innerText = 'Liveness check...';
        const ok = await waitFor(n);
        if (!ok) throw new Error('Liveness check failed (' + n + ' not detected)');
        if (latest) sharpSamples.push(sharpness(latest.detection.box));
        setPrompt('✔ Good');
        await sleep(250);
      }

      // Spoof check: printed/replayed faces tend to be blurry
      const avg = sharpSamples.reduce((a, b) => a + b, 0) / (sharpSamples.length || 1);
      console.log('sharpness avg:', avg.toFixed(1));
      // The number is shown so you can tune minSharpness from a phone without a console
      if (avg < CFG.minSharpness)
        throw new Error('Possible spoof detected (low image detail: ' + avg.toFixed(0) + ' / needs ' + CFG.minSharpness + ')');

      setPrompt('Look straight at the camera');
      await waitFrontal();
      mode = 'pass';
      setPrompt('');
      return { ok: true, challenges: names, sharpness: avg };
    } catch (e) {
      mode = 'fail';
      setPrompt('');
      setTimeout(() => { if (mode === 'fail') mode = 'idle'; }, 2000);
      return { ok: false, reason: e.message };
    }
  }

  function reset() { mode = 'idle'; setPrompt(''); }

  window.Liveness = { init, run, reset };
})();