// MMC Clinic — service worker
// Purpose: make the app installable and let the shell load when offline.
// Deliberately does NOT cache anything under /api/ — patient data must
// always come from the network, never a stale cache.

const CACHE_NAME = 'mmc-clinic-shell-v1';
const SHELL_FILES = ['/', '/manifest.json'];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_FILES))
      .catch(() => {}) // offline on first install — fine, just skip pre-caching
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(
        names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Clinic data: always network, never cached or served from cache.
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Only handle GET requests for the shell; let everything else pass through.
  if (event.request.method !== 'GET') return;

  // App shell: network-first (so updates are picked up immediately), with
  // a cached fallback for when the connection drops.
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy)).catch(() => {});
        return response;
      })
      .catch(() => caches.match(event.request).then((r) => r || caches.match('/')))
  );
});
