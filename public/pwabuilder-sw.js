const CACHE_NAME = 'my-artfive-shell-v7';
const SHELL_ASSETS = ['/', '/index.html', '/manifest.webmanifest', '/vendor/alpine-3.14.9.min.js'];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(SHELL_ASSETS);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith('my-artfive-') && key !== CACHE_NAME).map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);

  // Never cache API responses, authentication, payment state, customer records or tickets.
  if (url.origin === self.location.origin && url.pathname.startsWith('/api/')) return;

  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const response = await fetch(request);
        if (response && response.ok) {
          const cache = await caches.open(CACHE_NAME);
          cache.put('/', response.clone());
          cache.put('/index.html', response.clone());
        }
        return response;
      } catch {
        return (await caches.match(request)) || (await caches.match('/index.html')) || Response.error();
      }
    })());
    return;
  }

  const isSameOriginAsset = url.origin === self.location.origin;
  const isLibraryAsset = /\.(?:js|css|woff2?|ttf|otf)$/i.test(url.pathname) ||
    /fonts\.googleapis\.com|fonts\.gstatic\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com/.test(url.hostname);
  if (!isSameOriginAsset && !isLibraryAsset) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(request);

    // External CDN libraries must be network-first. In no-cors script requests,
    // a failed HTTP response can be opaque (status 0); never cache opaque responses,
    // because a cached CDN error can keep Alpine.js broken across app reloads.
    if (!isSameOriginAsset) {
      try {
        const response = await fetch(request);
        if (response && response.ok && response.type !== 'opaque') {
          await cache.put(request, response.clone());
        }
        return response;
      } catch {
        return cached || Response.error();
      }
    }

    if (cached) {
      event.waitUntil(fetch(request).then(response => {
        if (response && response.ok) return cache.put(request, response.clone());
      }).catch(() => {}));
      return cached;
    }
    try {
      const response = await fetch(request);
      if (response && response.ok) await cache.put(request, response.clone());
      return response;
    } catch {
      return cached || Response.error();
    }
  })());
});
