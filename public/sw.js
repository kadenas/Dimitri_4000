const CACHE_NAME = 'varadero-mosquera-v22';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/src/main.js',
  '/src/ui.js',
  '/src/balance.js',
  '/src/audio.js',
  '/src/save.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(key => (key !== CACHE_NAME) && caches.delete(key)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const request = event.request;
  event.respondWith(
    caches.match(request).then(hit =>
      hit || fetch(request).then(networkResponse => {
        if (request.method === 'GET' && new URL(request.url).origin === location.origin) {
          const copy = networkResponse.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
        }
        return networkResponse;
      }).catch(() => hit)
    )
  );
});
