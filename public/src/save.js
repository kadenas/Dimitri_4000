const KEY = 'astillero-state-v3';

export function load(defaultState) {
  try {
    const stored = localStorage.getItem(KEY);
    if (!stored) return structuredClone(defaultState);
    const parsed = JSON.parse(stored);
    return { ...structuredClone(defaultState), ...parsed };
  } catch (err) {
    console.warn('No se pudo cargar el estado guardado', err);
    return structuredClone(defaultState);
  }
}

export function save(state) {
  try {
    const clone = { ...state };
    localStorage.setItem(KEY, JSON.stringify(clone));
  } catch (err) {
    console.warn('No se pudo guardar el estado', err);
  }
}

export function clear() {
  try {
    localStorage.removeItem(KEY);
  } catch (err) {
    console.warn('No se pudo limpiar el estado', err);
  }
}
