// sounds.js - plays your audio files (success.wav, error.wav, warn.wav)
// Keep the three files in the same folder as the pages.
const Sound = (() => {
  const FILES = {
    success: 'success.wav',
    error:   'error.wav',
    warn:    'warn.wav'
  };

  // LOUDNESS: 1 = original file volume, 2 = double, 3 = triple ...
  const VOLUME = 2;

  const AC = window.AudioContext || window.webkitAudioContext;
  const ctx = new AC();
  const master = ctx.createGain();
  master.gain.value = VOLUME;
  const comp = ctx.createDynamicsCompressor();     // prevents crackling when loud
  master.connect(comp).connect(ctx.destination);

  const buffers = {};
  const plain = {};   // fallback players

  // Load the files right away (does not need a click)
  Object.entries(FILES).forEach(([name, url]) => {
    plain[name] = new Audio(url);
    plain[name].preload = 'auto';
    fetch(url)
      .then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status + ' (file not found?)');
        return r.arrayBuffer();
      })
      .then(b => new Promise((ok, no) => ctx.decodeAudioData(b, ok, no)))
      .then(buf => { buffers[name] = buf; })
      .catch(e => console.error('[Sound] could not load ' + url + ':', e));
  });

  function unlock() {
    if (ctx.state !== 'running') ctx.resume();
  }

  function play(name) {
    unlock();
    if (buffers[name]) {
      const src = ctx.createBufferSource();
      src.buffer = buffers[name];
      src.connect(master);
      src.start();
    } else if (plain[name]) {
      // fallback if the file is not decoded yet
      plain[name].currentTime = 0;
      plain[name].volume = 1;
      plain[name].play().catch(e => console.error('[Sound] blocked or missing:', e));
    }
  }

  return {
    unlock,
    success() { play('success'); },
    error()   { play('error'); },
    warn()    { play('warn'); }
  };
})();