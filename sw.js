/**
 * Paramount E-mart — Service Worker
 * =====================================
 * Strategy:
 *  - Core shell (CSS, JS, HTML) → Cache First, network fallback
 *  - API calls → Network First, cache fallback
 *  - Images → Cache First with 30-day expiry
 *  - Unknown → Network with offline fallback
 */

const CACHE_VERSION = 'pem-v2'; // E-mart rebranded
const CACHE_CORE    = CACHE_VERSION + '-core';
const CACHE_IMAGES  = CACHE_VERSION + '-images';
const CACHE_API     = CACHE_VERSION + '-api';

const CORE_ASSETS = [
  '/',
  '/index.html',
  '/tracking.html',
  '/receipt.html',
  '/css/style.css',
  '/css/popups.css',
  '/css/themes.css',
  '/js/theme.js',
  '/js/products.js',
  '/js/pds-analytics.js',
  '/js/pds-sync.js',
  '/js/store.js',
  '/js/shared.js',
  '/js/transport.js',
  '/js/pds-media.js',
  '/js/admin.js',
  '/images/logo.png',
  '/manifest.json',
];

const API_CACHE_ROUTES = [
  '/api/products',
  '/api/categories',
  '/api/shipments',
  '/api/site-settings',
  '/api/promo-codes',
  '/api/bulk-tiers',
];

// ── Install: pre-cache core shell ──────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_CORE).then(cache => {
      return cache.addAll(CORE_ASSETS.map(url => new Request(url, { cache: 'reload' })));
    }).then(() => self.skipWaiting())
  );
});

// ── Activate: remove old caches ────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k.startsWith('pes-') && !k.startsWith(CACHE_VERSION))
          .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: routing strategies ──────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET and cross-origin (payment SDKs, fonts, etc.)
  if (request.method !== 'GET') return;
  if (url.origin !== location.origin) return;

  const path = url.pathname;

  // API routes — Network First
  if (path.startsWith('/api/')) {
    event.respondWith(networkFirst(request, CACHE_API, 5000));
    return;
  }

  // Images — Cache First with fallback
  if (/\.(png|jpg|jpeg|gif|webp|svg|ico)$/i.test(path)) {
    event.respondWith(cacheFirst(request, CACHE_IMAGES));
    return;
  }

  // Core assets — Cache First
  event.respondWith(cacheFirst(request, CACHE_CORE));
});

// ── Strategy: Cache First ──────────────────────────────────
async function cacheFirst(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) cache.put(request, response.clone());
    return response;
  } catch {
    // Offline fallback for HTML
    if (request.headers.get('accept')?.includes('text/html')) {
      const fallback = await caches.match('/index.html');
      if (fallback) return fallback;
    }
    return new Response('Offline — please check your connection', {
      status: 503, headers: { 'Content-Type': 'text/plain' }
    });
  }
}

// ── Strategy: Network First ────────────────────────────────
async function networkFirst(request, cacheName, timeoutMs) {
  const cache = await caches.open(cacheName);
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const response = await fetch(request, { signal: controller.signal });
    clearTimeout(timer);
    if (response.ok) cache.put(request, response.clone());
    return response;
  } catch {
    const cached = await cache.match(request);
    if (cached) return cached;
    return new Response(JSON.stringify({ ok: false, error: 'Offline', cached: false }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// ── Background Sync: retry failed orders ──────────────────
self.addEventListener('sync', event => {
  if (event.tag === 'retry-orders') {
    event.waitUntil(retryPendingOrders());
  }
});

async function retryPendingOrders() {
  // Placeholder — extend if using BackgroundSync API for offline orders
}

// ── Push Notifications (future use) ───────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  const data = event.data.json();
  event.waitUntil(
    self.registration.showNotification(data.title || 'Paramount E-mart', {
      body:  data.body  || 'You have a new update.',
      icon:  '/images/logo.png',
      badge: '/images/logo.png',
      data:  { url: data.url || '/' },
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow(event.notification.data?.url || '/')
  );
});
