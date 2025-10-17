import * as ui from './ui.js';
import * as audio from './audio.js';
import { upgradesDef, jpsTotal, valorClick, getDef, getUpgradeLevel } from './balance.js';
import * as save from './save.js';

export const state = (window.Astillero && window.Astillero.state) || save.load({
  jornales: 0,
  jornalesPerSec: 0,
  baseClick: 1,
  upgrades: upgradesDef.map(u => ({ id: u.id, nivel: 0 })),
  bonus: { active: false, remaining: 0, cooldown: 0, duration: 30000, cooldownMax: 120000, multiplier: 2, permaMult: 1 },
  totals: { taps: 0, acumulados: 0 },
  achievements: { claimed: {}, progress: { taps: 0, totalJornales: 0, maxJps: 0, compras: 0, barcos: 0 } },
  settings: { audio: true, vibrate: true, notation: 'abbr' }
});

window.Astillero = Object.assign(window.Astillero || {}, { state });

audio.initOnFirstInteraction();
audio.setEnabled(!!state.settings.audio);

let saveTimer = 0;

export function doTap() {
  let gain = Number(valorClick(state)) || 0;
  if (state.bonus.active) gain *= state.bonus.multiplier;
  gain *= (state.bonus.permaMult || 1);
  state.jornales = Number(state.jornales) + gain;
  state.totals.taps = (state.totals.taps || 0) + 1;
  state.achievements.progress.taps++;
  if (state.settings.audio) audio.playTap();
  ui.renderHUD(state);
  ui.updateShop(state);
  ui.renderDock(state);
  requestSave();
  return gain;
}

export function toggleBonus() {
  if (!state.bonus.active && state.bonus.cooldown <= 0) {
    state.bonus.active = true;
    state.bonus.remaining = state.bonus.duration;
    state.bonus.cooldown = state.bonus.cooldownMax + state.bonus.duration;
    if (state.settings.audio) audio.startTide();
  }
}

export function buyUpgrade(id) {
  const record = state.upgrades.find(u => u.id === id);
  const def = getDef(id);
  if (!record || !def) return;
  const nivel = Number(record.nivel || 0);
  const cost = Math.floor(def.baseCoste * Math.pow(1.2, nivel) * (nivel > 25 ? Math.pow(1.03, nivel - 25) : 1));
  if (state.jornales >= cost) {
    state.jornales -= cost;
    record.nivel = nivel + 1;
    state.achievements.progress.compras++;
    if (state.settings.audio) audio.playUpgrade();
    ui.renderHUD(state);
    ui.updateShop(state);
    ui.renderDock(state);
    requestSave();
  }
}

export function getTotalsForVisuals(s) {
  const sumNiv = (s.upgrades || []).reduce((acc, u) => acc + (Number(u.nivel) || 0), 0);
  const barcos = Math.min(20, Math.floor(sumNiv / 5));
  const obreros = getUpgradeLevel(s, 'aprendices');
  const gruas = Math.floor((getUpgradeLevel(s, 'equipo') + getUpgradeLevel(s, 'capataz')) / 3);
  return { barcos, obreros, gruas };
}

function requestSave() {
  saveTimer = performance.now();
}

let prev = performance.now();
function frame(now) {
  const dt = now - prev;
  prev = now;

  if (state.bonus.active) {
    state.bonus.remaining -= dt;
    if (state.bonus.remaining <= 0) {
      state.bonus.active = false;
      state.bonus.remaining = 0;
      if (state.settings.audio) audio.stopTide();
    }
  }

  if (state.bonus.cooldown > 0) {
    state.bonus.cooldown -= dt;
    if (state.bonus.cooldown < 0) state.bonus.cooldown = 0;
  }

  const mult = (state.bonus.active ? state.bonus.multiplier : 1) * (state.bonus.permaMult || 1);
  state.jornalesPerSec = Number(jpsTotal(state)) * mult || 0;
  state.jornales = Number(state.jornales) + state.jornalesPerSec * (dt / 1000);
  state.achievements.progress.totalJornales += state.jornalesPerSec * (dt / 1000);
  state.achievements.progress.maxJps = Math.max(state.achievements.progress.maxJps || 0, state.jornalesPerSec || 0);

  ui.renderHUD(state);
  ui.updateShop(state);
  ui.renderDock(state);
  ui.renderAchievements(state);

  if (saveTimer && now - saveTimer >= 150) {
    save.save(state);
    saveTimer = 0;
  }

  requestAnimationFrame(frame);
}

window.addEventListener('DOMContentLoaded', () => {
  ui.initUI();
  ui.buildShop();
  ui.renderHUD(state);
  ui.updateShop(state);
  ui.renderDock(state);
  ui.renderAchievements(state);
  document.getElementById('nav-ach')?.addEventListener('click', () => ui.renderAchievements(state));
  requestAnimationFrame(frame);
});

Object.assign(window.Astillero, { doTap, toggleBonus, buyUpgrade, getTotalsForVisuals });
