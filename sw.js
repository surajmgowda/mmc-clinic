// Service worker for Male Madeshwara Clinic — caches the app shell (the
// single index.html file plus icons/manifest) so the app itself opens
// instantly, even on a slow connection. It deliberately does NOT cache
// anything under /api/ — clinic data must always come from the live
// server, never a stale local copy, so staff never see out-of-date
// patients, visits, or billing.
const CACHE_NAME = 'mmc-shell-v1';
const SHELL_FILES = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './icon-maskable-192.png',
  './icon-maskable-512.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(SHELL_FILES))
      .catch(() => { /* fine if a file's missing — shell caching just partly no-ops */ })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Clinic data: always network, never cached or served stale.
  if (url.pathname.startsWith('/api/')) return;

  // Only handle same-origin GET requests for the app shell itself;
  // everything else (Google Fonts, any other origin) passes straight through.
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;

  // Stale-while-revalidate: serve instantly from cache if we have it, and
  // refresh the cache in the background — falls back to cache if offline.
  event.respondWith(
    caches.match(event.request).then(cached => {
      const network = fetch(event.request)
        .then(response => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
          }
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
