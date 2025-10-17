import { buyUpgrade, doTap, toggleBonus } from './main.js';
import { upgradesDef, costeSiguiente, getUpgradeLevel, achievementsDef } from './balance.js';

let $contador, $jps, $bonusBar, $bonusText, $tapBoat, $tapFx;
let $navDock, $navShop, $navAch, $shopList, $achList, $achCount;
let $dockPanel, $shopPanel, $achPanel, $dockShips, $dockWorkers, $dockCranes;
const shopNodes = new Map();
let _lastPointerTs = 0;

export function initUI() {
  $contador = document.getElementById('contador') || $contador;
  $jps = document.getElementById('jps') || $jps;
  $bonusBar = document.getElementById('bonusBar') || $bonusBar;
  $bonusText = document.getElementById('bonusText') || $bonusText;
  $tapBoat = document.getElementById('tapBoat') || $tapBoat;
  $tapFx = document.getElementById('tapFx') || $tapFx;

  $dockPanel = document.getElementById('dockPanel') || $dockPanel;
  $shopPanel = document.getElementById('shopPanel') || $shopPanel;
  $achPanel = document.getElementById('achPanel') || $achPanel;
  $navDock = document.getElementById('nav-dock') || $navDock;
  $navShop = document.getElementById('nav-shop') || $navShop;
  $navAch = document.getElementById('nav-ach') || $navAch;

  $dockShips = document.getElementById('dockShips') || $dockShips;
  $dockWorkers = document.getElementById('dockWorkers') || $dockWorkers;
  $dockCranes = document.getElementById('dockCranes') || $dockCranes;
  $shopList = document.getElementById('shopList') || $shopList;
  $achList = document.getElementById('achList') || $achList;
  $achCount = document.getElementById('achCount') || $achCount;

  wireTapBoat();
  wireBottomNav();
}

function wireTapBoat() {
  if (!$tapBoat || $tapBoat.__wired) return;
  const onTap = ev => {
    const now = performance.now();
    if (now - _lastPointerTs < 140) return;
    _lastPointerTs = now;
    ev.preventDefault?.();
    ev.stopPropagation?.();
    const gain = doTap();
    showTapFloat(gain);
    spawnBolts(ev, 12 + (Math.random() * 8 | 0));
  };
  $tapBoat.addEventListener('pointerdown', onTap, { passive: false });
  $tapBoat.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); }, { capture: true });
  $tapBoat.__wired = true;
  if (!$tapFx) {
    const fx = document.createElement('div');
    fx.id = 'tapFx';
    $tapBoat.appendChild(fx);
    $tapFx = fx;
  }
}

export function renderHUD(state) {
  if (!$contador || !$jps || !$bonusBar || !$bonusText) initUI();
  if ($contador) $contador.textContent = fmt(state.jornales);
  if ($jps) $jps.textContent = `${fmt(state.jornalesPerSec)} Jornales/s`;
  const cd = state.bonus.cooldown;
  const total = state.bonus.cooldownMax + state.bonus.duration;
  const pct = state.bonus.active ? 100 : (cd > 0 ? 100 - Math.floor((cd / total) * 100) : 100);
  if ($bonusBar) $bonusBar.style.width = pct + '%';
  if ($bonusText) $bonusText.textContent = state.bonus.active ? 'Marea viva activa' : (cd > 0 ? 'Marea en enfriamiento' : 'Marea viva lista');
}

export function showTapFloat(gain) {
  if (!$tapFx) return;
  const node = document.createElement('div');
  node.className = 'tapFloat';
  node.textContent = `+${fmt(typeof gain === 'number' ? gain : 0)}`;
  node.style.left = '50%';
  node.style.top = '50%';
  node.style.transform = 'translate(-50%, -10%)';
  $tapFx.appendChild(node);
  setTimeout(() => node.remove(), 900);
}

function spawnBolts(ev, n) {
  if (!$tapFx || !$tapBoat) return;
  const rect = $tapBoat.getBoundingClientRect();
  const baseX = (ev?.clientX ?? rect.left + rect.width / 2) - rect.left;
  const baseY = (ev?.clientY ?? rect.top + rect.height / 2) - rect.top;
  for (let i = 0; i < n; i++) {
    const p = document.createElement('div');
    p.className = 'bolt ' + (i % 3 === 0 ? 'r1' : i % 3 === 1 ? 'r2' : '');
    const dx = (Math.random() * 84 - 42).toFixed(1) + 'px';
    const dy = (60 + Math.random() * 90).toFixed(1) + 'px';
    const rot = (Math.random() * 180 - 90).toFixed(1) + 'deg';
    p.style.setProperty('--dx', dx);
    p.style.setProperty('--dy', dy);
    p.style.setProperty('--rot', rot);
    p.style.left = Math.max(6, Math.min(rect.width - 6, baseX + (Math.random() * 16 - 8))) + 'px';
    p.style.top = Math.max(6, Math.min(rect.height - 6, baseY + (Math.random() * 16 - 8))) + 'px';
    $tapFx.appendChild(p);
    setTimeout(() => p.remove(), 740);
  }
}

export function renderDock(state) {
  if (!$dockShips || !$dockWorkers || !$dockCranes) return;
  const ship = `<svg class="ship" viewBox="0 0 24 24"><path fill="#FF8C00" d="M3 14h18l-2 4H5z"/><path fill="#c7e7ff" d="M6 10l5 3H6z"/><rect x="11" y="8" width="2" height="3" fill="#c7e7ff"/></svg>`;
  const worker = `<svg class="worker" viewBox="0 0 24 24"><circle cx="12" cy="8" r="3" fill="#ffd27a"/><rect x="8" y="12" width="8" height="8" rx="2" fill="#4aa3ff"/></svg>`;
  const crane = `<svg class="crane" viewBox="0 0 24 24"><path d="M4 20h16" stroke="#a0c7ff" stroke-width="2"/><path d="M6 20V8l8-4 4 4" stroke="#a0c7ff" stroke-width="2" fill="none"/><circle cx="18" cy="12" r="2" fill="#a0c7ff"/></svg>`;
  const totals = window.Astillero?.getTotalsForVisuals ? window.Astillero.getTotalsForVisuals(state) : { barcos: 0, obreros: 0, gruas: 0 };
  $dockShips.innerHTML = ship.repeat(Math.max(0, totals.barcos));
  $dockWorkers.innerHTML = worker.repeat(Math.max(0, totals.obreros));
  $dockCranes.innerHTML = crane.repeat(Math.max(0, totals.gruas));
}

function wireBottomNav() {
  if ($navDock && !$navDock.__wired) {
    $navDock.addEventListener('click', () => { openPanel('dock'); setCurrent($navDock); });
    $navDock.__wired = true;
  }
  if ($navShop && !$navShop.__wired) {
    $navShop.addEventListener('click', () => { openPanel('shop'); setCurrent($navShop); });
    $navShop.__wired = true;
  }
  if ($navAch && !$navAch.__wired) {
    $navAch.addEventListener('click', () => {
      openPanel('ach');
      setCurrent($navAch);
      renderAchievements(window.Astillero?.state);
    });
    $navAch.__wired = true;
  }
}

function openPanel(which) {
  $dockPanel = document.getElementById('dockPanel') || $dockPanel;
  $shopPanel = document.getElementById('shopPanel') || $shopPanel;
  $achPanel = document.getElementById('achPanel') || $achPanel;
  const open = (el, v) => { if (el) { el.open = v; el.scrollIntoView?.({ block: 'nearest' }); } };
  open($dockPanel, which === 'dock');
  open($shopPanel, which === 'shop');
  open($achPanel, which === 'ach');
}

function setCurrent(btn) {
  [$navDock, $navShop, $navAch].forEach(b => b && b.setAttribute('aria-current', String(b === btn)));
}

export function buildShop() {
  if (!$shopList) initUI();
  if (!$shopList) return;
  $shopList.innerHTML = '';
  upgradesDef.forEach(def => {
    const node = document.createElement('article');
    node.className = 'upgrade';
    node.dataset.id = def.id;
    node.innerHTML = `
      <header>
        <h3>${def.nombre}</h3>
        <span class="nivel">Nivel 0</span>
      </header>
      <p>${def.descripcion}</p>
      <footer class="shop-foot">
        <span class="coste">Coste: ${fmt(def.baseCoste)}</span>
        <button type="button">Comprar</button>
      </footer>
    `;
    const button = node.querySelector('button');
    button.addEventListener('click', () => buyUpgrade(def.id));
    shopNodes.set(def.id, node);
    $shopList.appendChild(node);
  });
}

export function updateShop(state) {
  if (!shopNodes.size) buildShop();
  const saldo = Number(state.jornales || 0);
  shopNodes.forEach((node, id) => {
    const def = upgradesDef.find(u => u.id === id);
    const nivel = getUpgradeLevel(state, id);
    const coste = costeSiguiente(def, nivel);
    node.querySelector('.nivel').textContent = `Nivel ${nivel}`;
    node.querySelector('.coste').textContent = `Coste: ${fmt(coste)}`;
    const btn = node.querySelector('button');
    btn.disabled = saldo < coste;
  });
}

export function renderAchievements(state) {
  if (!$achList) initUI();
  if (!$achList) return;
  $achList.innerHTML = '';
  let obtained = 0;
  achievementsDef.forEach(def => {
    const achieved = !!def.check?.(state);
    if (achieved) {
      obtained += 1;
      if (state?.achievements) {
        state.achievements.claimed = state.achievements.claimed || {};
        state.achievements.claimed[def.id] = true;
      }
    }
    const item = document.createElement('div');
    item.className = 'achievement';
    item.setAttribute('aria-checked', achieved ? 'true' : 'false');
    item.innerHTML = `
      <strong>${def.nombre}</strong>
      <small>${def.descripcion}</small>
      <span>${achieved ? '✅ Completado' : '—'}</span>
    `;
    $achList.appendChild(item);
  });
  if ($achCount) $achCount.textContent = `${obtained}/${achievementsDef.length}`;
}

export function toggleBonusUI() {
  toggleBonus();
}

function fmt(n) {
  const num = Number(n) || 0;
  if (Math.abs(num) >= 1e12) return num.toExponential(2).replace('+', '');
  if (Math.abs(num) >= 1e9) return (num / 1e9).toFixed(2) + 'B';
  if (Math.abs(num) >= 1e6) return (num / 1e6).toFixed(2) + 'M';
  if (Math.abs(num) >= 1e3) return (num / 1e3).toFixed(2) + 'K';
  return Math.floor(num).toString();
}
