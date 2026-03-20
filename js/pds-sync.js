/**
 * PDS Sync — Client ↔ Server Data Bridge
 * ========================================
 * Automatically mirrors every localStorage write to the server.
 * Works silently in the background. Falls back gracefully when
 * the server is offline — the store always works either way.
 *
 * HOW IT WORKS:
 *  - Intercepts saveProducts(), saveOrders(), saveShipments(),
 *    saveCategories(), addOrder(), saveReview() at the JS level
 *  - On every call: writes to localStorage (original behaviour)
 *    THEN posts to the server API asynchronously
 *  - On page load: pulls latest data FROM the server and seeds
 *    localStorage so all devices stay in sync
 *  - Queues failed writes and retries them when connectivity
 *    is remartd (up to 3 retries with backoff)
 *
 * Load this file AFTER products.js and BEFORE store.js / admin.js
 */

(function() {
  'use strict';

  // ── Config ──────────────────────────────────────────────
  const SERVER   = (function() {
    // Auto-detect: if served from the Node server, use same origin.
    // If opened as a file:// or different host, fall back to localhost:3000.
    const loc = window.location;
    if (loc.protocol === 'http:' || loc.protocol === 'https:') {
      return loc.protocol + '//' + loc.host;
    }
    return 'http://localhost:3000';
  })();

  // Build admin headers using the secure session token (set by admin.js on login)
  function getAdminHeader() {
    var tok = sessionStorage.getItem('pes_admin_token');
    if (!tok) return {};
    return { 'X-PDS-Session': tok };
  }
  var ADMIN_HEADER = {}; // legacy compat - replaced by getAdminHeader()
  const CONTENT_JSON = { 'Content-Type': 'application/json' };
  const RETRY_DELAYS = [4000, 12000, 30000]; // Gentler retry to avoid lag // ms between retries

  // ── State ───────────────────────────────────────────────
  let _online        = false;     // server reachable?
  let _syncQueue     = [];        // failed writes waiting to retry
  let _retryTimer    = null;
  let _initialised   = false;

  // ── Helpers ─────────────────────────────────────────────
  function isAdmin() {
    // Check new secure token first, fall back to legacy flag
    return !!sessionStorage.getItem('pes_admin_token') ||
           sessionStorage.getItem('pes_admin') === 'true';
  }

  function post(endpoint, data, headers) {
    return fetch(SERVER + endpoint, {
      method:  'POST',
      headers: Object.assign({}, CONTENT_JSON, headers || {}),
      body:    JSON.stringify(data),
    });
  }

  function get(endpoint, headers) {
    return fetch(SERVER + endpoint, {
      headers: Object.assign({}, headers || {}),
    });
  }

  function queue(endpoint, data, headers) {
    _syncQueue.push({ endpoint, data, headers, retries: 0, ts: Date.now() });
    scheduleRetry();
  }

  function scheduleRetry() {
    if (_retryTimer) return;
    _retryTimer = setTimeout(flushQueue, RETRY_DELAYS[0]);
  }

  async function flushQueue() {
    _retryTimer = null;
    if (!_syncQueue.length) return;
    const remaining = [];
    for (const item of _syncQueue) {
      try {
        const r = await post(item.endpoint, item.data, item.headers || getAdminHeader());
        if (!r.ok) throw new Error('HTTP ' + r.status);
        // success — drop from queue
      } catch (e) {
        item.retries++;
        if (item.retries < RETRY_DELAYS.length) {
          remaining.push(item);
        }
        // else: drop after max retries
      }
    }
    _syncQueue = remaining;
    if (_syncQueue.length) scheduleRetry();
  }

  // ── Fire-and-forget push ─────────────────────────────────
  function push(endpoint, data, adminRequired) {
    var hdr = adminRequired ? getAdminHeader() : {};
    if (!_online) { queue(endpoint, data, hdr); return; }
    post(endpoint, data, hdr)
      .catch(() => queue(endpoint, data, hdr));
  }

  // ── Server health check ──────────────────────────────────
  async function pingServer() {
    try {
      var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
      var timeoutId = null;
      if (controller) {
        timeoutId = setTimeout(function() { controller.abort(); }, 4000);
      }
      var opts = controller ? { signal: controller.signal } : {};
      var r = await fetch(SERVER + '/api/health', opts);
      if (timeoutId) clearTimeout(timeoutId);
      _online = r.ok;
    } catch (e) {
      _online = false;
    }
    return _online;
  }

  // ── Pull latest data from server on page load ────────────
  async function pullFromServer() {
    if (!_online) return;
    var _productsUpdated = false;
    var _categoriesUpdated = false;

    try {
      // Pull products (public)
      const pr = await get('/api/products');
      if (pr.ok) {
        const d = await pr.json();
        if (Array.isArray(d.products) && d.products.length) {
          localStorage.setItem('pes_products', JSON.stringify(d.products));
          _productsUpdated = true;
        }
      }
    } catch(e) {}

    try {
      // Pull categories (public)
      const cr = await get('/api/categories');
      if (cr.ok) {
        const d = await cr.json();
        if (Array.isArray(d.categories) && d.categories.length) {
          localStorage.setItem('pes_categories', JSON.stringify(d.categories));
          _categoriesUpdated = true;
        }
      }
    } catch(e) {}

    // Always re-render after pulling — ensures UI is up to date
    if (typeof renderFeaturedInline === 'function') {
      setTimeout(renderFeaturedInline, 0);
    }
    if (typeof renderCategoryStrip === 'function') {
      setTimeout(renderCategoryStrip, 0);
    }

    try {
      // Pull shipments (public — needed for tracking page)
      const sr = await get('/api/shipments');
      if (sr.ok) {
        const d = await sr.json();
        if (Array.isArray(d.shipments) && d.shipments.length) {
          localStorage.setItem('pes_shipments', JSON.stringify(d.shipments));
        }
      }
    } catch(e) {}

    // Pull keys + settings (all devices, seeds localStorage)
    try {
      const kr = await get('/api/get-keys', getAdminHeader());
      if (kr.ok) {
        const d = await kr.json();
        if (d.seed) {
          Object.entries(d.seed).forEach(function(kv) {
            if (kv[1]) localStorage.setItem(kv[0], kv[1]);
          });
        }
      }
    } catch(e) {}

    // Pull site settings (public)
    try {
      var settingsR = await get('/api/site-settings');
      if (settingsR.ok) {
        var d = await settingsR.json();
        if (d.settings) {
          applyServerSettings(d.settings);
          // Trigger UI refresh with newly seeded settings
          if (typeof loadAdminContent  === 'function') loadAdminContent();
          if (typeof applyFooterConfig === 'function') applyFooterConfig();
          if (typeof renderFeaturedInline  === 'function') renderFeaturedInline();
          if (typeof renderCategoryStrip   === 'function') renderCategoryStrip();
        }
      }
    } catch(e) {}

    // Pull promo codes (public — needed at checkout)
    try {
      var promoR = await get('/api/promo-codes');
      if (promoR.ok) {
        var pd = await promoR.json();
        if (pd.promoCodes) {
          localStorage.setItem('pes_promo_codes', JSON.stringify(pd.promoCodes));
        }
      }
    } catch(e) {}

    // Pull bulk tiers (public — needed at checkout)
    try {
      var tiersR = await get('/api/bulk-tiers');
      if (tiersR.ok) {
        var td = await tiersR.json();
        if (td.tiers) {
          localStorage.setItem('pes_bulk_tiers', JSON.stringify(td.tiers));
        }
      }
    } catch(e) {}

    // Admin: also pull orders
    if (isAdmin()) {
      try {
        const or = await get('/api/orders', getAdminHeader());
        if (or.ok) {
          const d = await or.json();
          if (Array.isArray(d.orders) && d.orders.length) {
            localStorage.setItem('pes_orders', JSON.stringify(d.orders));
          }
        }
      } catch(e) {}
    }
  }

  // Apply server-stored site settings to localStorage
  function applyServerSettings(settings) {
    const map = {
      marquee:      'pes_marquee',
      storeHero:    'pes_store_hero',
      trustStrip:   'pes_trust_strip',
      footerConfig: 'pes_footer_config',
      seo:          'pes_seo',
      banner:       'pes_banner',
      trackingText: 'pes_tracking_text',
      sectionLabels:'pes_section_labels',
      promoCodes:   'pes_promo_codes',
      bulkTiers:    'pes_bulk_tiers',
    };
    Object.entries(map).forEach(function(entry) {
      var key = entry[0], lsKey = entry[1];
      if (settings[key] !== undefined && settings[key] !== null) {
        var val = (typeof settings[key] === 'string') ? settings[key] : JSON.stringify(settings[key]);
        if (val) localStorage.setItem(lsKey, val);
      }
    });
  }

  // ── Intercept saveProducts ───────────────────────────────
  var _origSaveProducts = window.saveProducts;
  window.saveProducts = function(products) {
    if (typeof _origSaveProducts === 'function') _origSaveProducts(products);
    else localStorage.setItem('pes_products', JSON.stringify(products));
    push('/api/products', { products: products }, true);
  };

  // ── Intercept saveCategories ─────────────────────────────
  var _origSaveCategories = window.saveCategories;
  window.saveCategories = function(cats) {
    if (typeof _origSaveCategories === 'function') _origSaveCategories(cats);
    else localStorage.setItem('pes_categories', JSON.stringify(cats));
    push('/api/categories', { categories: cats }, true);
  };

  // ── Intercept saveOrders ─────────────────────────────────
  var _origSaveOrders = window.saveOrders;
  window.saveOrders = function(orders) {
    if (typeof _origSaveOrders === 'function') _origSaveOrders(orders);
    else localStorage.setItem('pes_orders', JSON.stringify(orders));
    if (isAdmin()) push('/api/orders', { orders: orders }, true);
  };

  // ── Intercept addOrder (single order at checkout) ────────
  var _origAddOrder = window.addOrder;
  window.addOrder = function(order) {
    if (typeof _origAddOrder === 'function') _origAddOrder(order);
    else {
      var orders = JSON.parse(localStorage.getItem('pes_orders') || '[]');
      orders.unshift(order);
      localStorage.setItem('pes_orders', JSON.stringify(orders));
    }
    // Always push individual orders — no admin required for checkout
    push('/api/order', order, false);
  };

  // ── Intercept saveShipments ──────────────────────────────
  var _origSaveShipments = window.saveShipments;
  window.saveShipments = function(ships) {
    if (typeof _origSaveShipments === 'function') _origSaveShipments(ships);
    else localStorage.setItem('pes_shipments', JSON.stringify(ships));
    push('/api/shipments', { shipments: ships }, true);
  };

  // ── Intercept addShipment (single shipment at checkout) ──
  var _origAddShipment = window.addShipment;
  window.addShipment = function(ship) {
    if (typeof _origAddShipment === 'function') _origAddShipment(ship);
    else {
      var ships = JSON.parse(localStorage.getItem('pes_shipments') || '[]');
      ships.unshift(ship);
      localStorage.setItem('pes_shipments', JSON.stringify(ships));
    }
    push('/api/shipment', ship, false);
  };

  // ── Intercept saveReview ─────────────────────────────────
  var _origSaveReview = window.saveReview;
  window.saveReview = function(productId, review) {
    if (typeof _origSaveReview === 'function') _origSaveReview(productId, review);
    else {
      var reviews = JSON.parse(localStorage.getItem('pes_reviews_' + productId) || '[]');
      reviews.unshift(review);
      localStorage.setItem('pes_reviews_' + productId, JSON.stringify(reviews.slice(0, 50)));
    }
    push('/api/reviews/' + productId, review, false);
  };

  // ── Intercept saveSeoSettings ────────────────────────────
  // SEO, footer, hero, marquee, trust strip → push to /api/site-settings
  function pushSiteSettings() {
    var settings = {
      marquee:      localStorage.getItem('pes_marquee')        || '',
      storeHero:    localStorage.getItem('pes_store_hero')     || '{}',
      trustStrip:   localStorage.getItem('pes_trust_strip')    || '[]',
      footerConfig: localStorage.getItem('pes_footer_config')  || '{}',
      seo:          localStorage.getItem('pes_seo')            || '{}',
      banner:       localStorage.getItem('pes_banner')         || '{}',
      trackingText: localStorage.getItem('pes_tracking_text')  || '{}',
      sectionLabels:localStorage.getItem('pes_section_labels') || '{}',
      bulkTiers:    localStorage.getItem('pes_bulk_tiers')     || '[]',
      promoCodes:   localStorage.getItem('pes_promo_codes')    || '[]',
    };
    push('/api/site-settings', { settings: settings }, true);
  }

  // Expose so the admin panel can call it after any settings save
  window.PDS_pushSiteSettings = pushSiteSettings;

  // ── Expose sync status ───────────────────────────────────
  window.PDS_SYNC = {
    isOnline:   function() { return _online; },
    ping:       pingServer,
    pullAll:    pullFromServer,
    pushQueue:  flushQueue,
    queueSize:  function() { return _syncQueue.length; },
    server:     SERVER,
  };

  // ── Init ─────────────────────────────────────────────────
  async function init() {
    if (_initialised) return;
    _initialised = true;
    await pingServer();
    if (_online) {
      await pullFromServer();
    }
    // Re-ping every 60 seconds to detect reconnection
    setInterval(async function() {
      var wasOnline = _online;
      await pingServer();
      if (!wasOnline && _online) {
        // Just came back online — push queue and re-pull
        flushQueue();
        pullFromServer();
      }
    }, 60000);
  }

  // Run after DOM ready so all function definitions are in place
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    // Already ready (script loaded at bottom of body or deferred)
    setTimeout(init, 0);
  }

})();
