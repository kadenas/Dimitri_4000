let ctx = null;
let enabled = true;
let unlocked = false;
let tideNodes = null;

export function initOnFirstInteraction() {
  if (unlocked) return;
  const resume = () => {
    try {
      if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
      if (ctx.state === 'suspended') ctx.resume();
      unlocked = true;
    } catch (err) {
      console.warn('AudioContext resume failed', err);
    }
  };
  window.addEventListener('pointerdown', resume, { once: true, capture: true });
  window.addEventListener('keydown', resume, { once: true, capture: true });
}

export function setEnabled(on) {
  enabled = !!on;
  if (!enabled) stopTide();
}

export function isEnabled() {
  return !!enabled;
}

function beep(freq = 440, dur = 0.08, type = 'square', gain = 0.04) {
  if (!enabled) return;
  if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
  const t = ctx.currentTime;
  const osc = ctx.createOscillator();
  const g = ctx.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(freq, t);
  g.gain.setValueAtTime(0, t);
  g.gain.linearRampToValueAtTime(gain, t + 0.006);
  g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
  osc.connect(g).connect(ctx.destination);
  osc.start(t);
  osc.stop(t + dur + 0.05);
}

export function playTap() {
  const f = 420 + Math.random() * 60;
  beep(f, 0.07, 'square', 0.05);
}

export function playUpgrade() {
  beep(360, 0.06, 'sawtooth', 0.05);
  setTimeout(() => beep(520, 0.06, 'sawtooth', 0.04), 60);
}

export function playAchievement() {
  beep(520, 0.07, 'triangle', 0.07);
  setTimeout(() => beep(780, 0.07, 'triangle', 0.07), 60);
  setTimeout(() => beep(1040, 0.09, 'triangle', 0.07), 120);
}

export function playShip() {
  beep(300, 0.08, 'sine', 0.06);
  setTimeout(() => beep(600, 0.06, 'sine', 0.05), 70);
}

export function playFlash() {
  beep(900, 0.03, 'square', 0.05);
}

export function startTide() {
  if (!enabled) return;
  if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
  if (tideNodes) return;
  const t = ctx.currentTime;
  const o1 = ctx.createOscillator();
  const o2 = ctx.createOscillator();
  const g = ctx.createGain();
  g.gain.setValueAtTime(0, t);
  g.gain.linearRampToValueAtTime(0.08, t + 0.35);
  o1.type = 'sine';
  o2.type = 'triangle';
  o1.frequency.setValueAtTime(0.6, t);
  o2.frequency.setValueAtTime(2.2, t);
  o1.connect(g);
  o2.connect(g);
  g.connect(ctx.destination);
  o1.start(t);
  o2.start(t);
  tideNodes = { o1, o2, g };
}

export function stopTide() {
  if (!tideNodes) return;
  const t = ctx.currentTime;
  tideNodes.g.gain.cancelScheduledValues(t);
  tideNodes.g.gain.setValueAtTime(tideNodes.g.gain.value, t);
  tideNodes.g.gain.linearRampToValueAtTime(0, t + 0.3);
  setTimeout(() => {
    tideNodes.o1.stop();
    tideNodes.o2.stop();
    tideNodes = null;
  }, 350);
}
