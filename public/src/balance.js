export const upgradesDef = [
  { id: 'aprendices', nombre: 'Aprendices', descripcion: 'Contrata manos extra para trabajos ligeros.', baseCoste: 15, jps: 0.3, click: 0 },
  { id: 'equipo', nombre: 'Equipo neumático', descripcion: 'Herramientas modernas agilizan la carena.', baseCoste: 50, jps: 0.9, click: 0.2 },
  { id: 'capataz', nombre: 'Capataz veterano', descripcion: 'Organiza turnos y mejora la eficiencia.', baseCoste: 120, jps: 2.5, click: 0.5 },
  { id: 'grua', nombre: 'Grúa telescópica', descripcion: 'Mueve cascos pesados sin esfuerzo.', baseCoste: 320, jps: 6, click: 0 },
  { id: 'diques', nombre: 'Diques adicionales', descripcion: 'Permite reparar más barcos en paralelo.', baseCoste: 900, jps: 15, click: 0 },
];

export const achievementsDef = [
  { id: 'primer-golpe', nombre: 'Primer golpe', descripcion: 'Realiza 1 reparación manual.', check: s => (s?.achievements?.progress?.taps || 0) >= 1 },
  { id: 'diez-golpes', nombre: 'Diez mareas', descripcion: 'Acumula 10 toques en la marea viva.', check: s => (s?.achievements?.progress?.taps || 0) >= 10 },
  { id: 'aprendices', nombre: 'Cuadrilla montada', descripcion: 'Compra 5 mejoras en total.', check: s => (s?.achievements?.progress?.compras || 0) >= 5 },
  { id: 'millon', nombre: 'Marea abundante', descripcion: 'Alcanza 1 000 jornales acumulados.', check: s => (s?.achievements?.progress?.totalJornales || 0) >= 1000 },
  { id: 'velocidad', nombre: 'Astillero exprés', descripcion: 'Supera los 50 jornales por segundo.', check: s => (s?.achievements?.progress?.maxJps || 0) >= 50 },
];

export function getDef(id) {
  return upgradesDef.find(u => u.id === id);
}

export function costeSiguiente(def, nivel = 0) {
  return Math.floor(def.baseCoste * Math.pow(1.2, nivel));
}

export function getUpgradeLevel(state, id) {
  const upgrade = state?.upgrades?.find(u => u.id === id);
  return Number(upgrade?.nivel || 0);
}

export function valorClick(state) {
  const base = Number(state?.baseClick ?? 1);
  const bonus = (state?.upgrades || []).reduce((acc, u) => {
    const def = getDef(u.id);
    const extra = def?.click || 0;
    return acc + Number(u.nivel || 0) * extra;
  }, 0);
  return base + bonus;
}

export function jpsTotal(state) {
  return (state?.upgrades || []).reduce((acc, u) => {
    const def = getDef(u.id);
    const rate = def?.jps || 0;
    return acc + Number(u.nivel || 0) * rate;
  }, 0);
}

export function isAchieved(state, id) {
  return !!state?.achievements?.claimed?.[id];
}
