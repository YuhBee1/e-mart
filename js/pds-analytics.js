/**
 * PDS Analytics — Client-side Page Tracking
 * ===========================================
 * Silently pings /api/pageview on every page load.
 * No cookies, no third parties. Data stays on your server.
 * Tracks: page path, referrer, device type, session duration.
 *
 * Load this in <head> of every page (it's tiny and non-blocking).
 */

(function() {
  'use strict';

  var SERVER = (function() {
    var loc = window.location;
    return (loc.protocol === 'http:' || loc.protocol === 'https:')
      ? loc.protocol + '//' + loc.host
      : 'http://localhost:3000';
  })();

  // Session start time — for duration tracking
  var _sessionStart = Date.now();

  // Device type
  function getDevice() {
    var ua = navigator.userAgent;
    if (/Mobi|Android|iPhone|iPad/i.test(ua)) return 'mobile';
    if (/Tablet|iPad/i.test(ua)) return 'tablet';
    return 'desktop';
  }

  // Referrer source (simplified, no PII)
  function getReferrerSource() {
    var ref = document.referrer;
    if (!ref) return 'direct';
    if (ref.includes('google'))   return 'google';
    if (ref.includes('facebook')) return 'facebook';
    if (ref.includes('twitter') || ref.includes('x.com')) return 'twitter';
    if (ref.includes('instagram'))return 'instagram';
    if (ref.includes('whatsapp')) return 'whatsapp';
    if (ref.includes(window.location.hostname)) return 'internal';
    return 'referral';
  }

  function pingPageview() {
    var data = {
      page:    window.location.pathname,
      title:   document.title,
      ref:     getReferrerSource(),
      device:  getDevice(),
      ts:      Date.now(),
    };
    // Use sendBeacon if available (non-blocking, survives page unload)
    if (navigator.sendBeacon) {
      var blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
      navigator.sendBeacon(SERVER + '/api/pageview', blob);
    } else {
      fetch(SERVER + '/api/pageview', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(data),
        keepalive: true,
      }).catch(function() {});
    }
  }

  // Ping session duration on page unload
  function pingDuration() {
    var duration = Math.round((Date.now() - _sessionStart) / 1000);
    var data = {
      page:     window.location.pathname,
      duration: duration,
      type:     'duration',
      ts:       Date.now(),
    };
    if (navigator.sendBeacon) {
      navigator.sendBeacon(SERVER + '/api/pageview', new Blob([JSON.stringify(data)], { type: 'application/json' }));
    }
  }

  // Fire pageview ping after page loads
  if (document.readyState === 'complete') {
    // Delay analytics ping so it doesn't compete with critical page renders
  setTimeout(pingPageview, 2500);
  } else {
    window.addEventListener('load', pingPageview);
  }

  // Track duration on exit
  window.addEventListener('pagehide', pingDuration);
  window.addEventListener('beforeunload', pingDuration);

})();
