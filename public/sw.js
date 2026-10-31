// Minimaler Service Worker: macht die App installierbar und lädt die Oberfläche offline.
const C = 'km-v1', FILES = ['/', '/index.html', '/style.css', '/signal.js', '/app.js', '/icon.svg', '/manifest.webmanifest'];
self.addEventListener('install', (e) => e.waitUntil(caches.open(C).then((c) => c.addAll(FILES))));
self.addEventListener('fetch', (e) => e.respondWith(fetch(e.request).catch(() => caches.match(e.request))));
