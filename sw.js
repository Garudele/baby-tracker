const CACHE = 'baby-tracker-v36';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './recipes.json',
  './milestones.json',
  './privacy.html',
  './terms.html'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('message', e => {
  if (e.data === 'SKIP_WAITING') self.skipWaiting();
});

// Network-first for HTML (always get fresh app), cache-first for assets
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  // Nunca tocar el API — siempre a la red, sin caché
  if (new URL(e.request.url).pathname.includes('/api/')) return;
  const isHTML = e.request.mode === 'navigate' ||
                 e.request.destination === 'document' ||
                 e.request.url.endsWith('.html') ||
                 e.request.url.endsWith('/');
  if (isHTML) {
    e.respondWith(
      fetch(e.request).then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      }).catch(() => caches.match(e.request).then(c => c || caches.match('./index.html')))
    );
  } else {
    e.respondWith(
      caches.match(e.request).then(cached => cached || fetch(e.request).then(res => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
        }
        return res;
      }))
    );
  }
});

// ===== PUSH NOTIFICATIONS =====
self.addEventListener('push', (event) => {
  let data = { title: 'Baby Tracker', body: 'Tienes una notificación' };
  try {
    if (event.data) data = { ...data, ...event.data.json() };
  } catch (e) {
    try { data.body = event.data.text(); } catch {}
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: 'icon-192.png',
      badge: 'icon-192.png',
      tag: data.tag || 'baby-tracker',
      data: data,
      renotify: true,
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of clients) {
      if (c.url.includes(self.location.host)) {
        return c.focus();
      }
    }
    return self.clients.openWindow('/');
  })());
});
