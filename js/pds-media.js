/**
 * PDS Media — Download Protection + Fullscreen Lightbox
 * =======================================================
 * 1. Blocks right-click save, drag-to-desktop, and long-press
 *    on all product images and videos.
 * 2. Provides a fullscreen lightbox with:
 *    - Slide navigation (prev/next buttons + dot indicators)
 *    - Thumbnail strip
 *    - Keyboard arrow / Escape support
 *    - Touch swipe support (mobile)
 *    - Expand button on product cards and product modal
 * 3. Product card slides get prev/next arrow buttons for
 *    manual navigation (not just auto-advance).
 *
 * Load after store.js. Works on index.html and tracking.html.
 */

(function() {
  'use strict';

  // ── State ──────────────────────────────────────────────
  var _lb = {
    images:   [],   // array of src strings
    captions: [],   // array of caption strings
    index:    0,
    open:     false,
  };
  var _swipeStartX = 0;
  var _swipeStartY = 0;

  // ── Inject lightbox HTML once ──────────────────────────
  function injectLightboxHTML() {
    if (document.getElementById('pesLightbox')) return;
    var el = document.createElement('div');
    el.id = 'pesLightbox';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'true');
    el.setAttribute('aria-label', 'Product image fullscreen view');
    el.innerHTML = [
      '<div class="pes-lb-bar">',
        '<span class="pes-lb-counter" id="pesLbCounter"></span>',
        '<span class="pes-lb-product-name" id="pesLbCaption"></span>',
        '<button class="pes-lb-close" onclick="PES_LB.close()" aria-label="Close">✕</button>',
      '</div>',
      '<div class="pes-lb-stage" id="pesLbStage">',
        '<button class="pes-lb-prev" onclick="PES_LB.prev()" aria-label="Previous">‹</button>',
        '<img class="pes-lb-img" id="pesLbImg" src="" alt="" draggable="false"/>',
        '<video class="pes-lb-video" id="pesLbVideo" controls style="display:none;"></video>',
        '<button class="pes-lb-next" onclick="PES_LB.next()" aria-label="Next">›</button>',
      '</div>',
      '<div class="pes-lb-thumbs" id="pesLbThumbs"></div>',
    ].join('');
    document.body.appendChild(el);

    // Close on backdrop click (not on image/buttons)
    el.addEventListener('click', function(e) {
      if (e.target === el || e.target.id === 'pesLbStage') PES_LB.close();
    });

    // Keyboard nav
    document.addEventListener('keydown', function(e) {
      if (!_lb.open) return;
      if (e.key === 'ArrowLeft')  { PES_LB.prev(); e.preventDefault(); }
      if (e.key === 'ArrowRight') { PES_LB.next(); e.preventDefault(); }
      if (e.key === 'Escape')     { PES_LB.close(); e.preventDefault(); }
    });

    // Touch swipe
    el.addEventListener('touchstart', function(e) {
      _swipeStartX = e.changedTouches[0].clientX;
      _swipeStartY = e.changedTouches[0].clientY;
    }, { passive: true });
    el.addEventListener('touchend', function(e) {
      var dx = e.changedTouches[0].clientX - _swipeStartX;
      var dy = e.changedTouches[0].clientY - _swipeStartY;
      if (Math.abs(dx) > Math.abs(dy) && Math.abs(dx) > 40) {
        if (dx < 0) PES_LB.next(); else PES_LB.prev();
      }
    }, { passive: true });
  }

  // ── Lightbox API ───────────────────────────────────────
  window.PES_LB = {

    open: function(images, startIndex, captions) {
      _lb.images   = Array.isArray(images) ? images : [images];
      _lb.captions = captions || [];
      _lb.index    = startIndex || 0;
      _lb.open     = true;
      injectLightboxHTML();
      PES_LB.render();
      document.getElementById('pesLightbox').classList.add('open');
      document.body.style.overflow = 'hidden';
    },

    close: function() {
      var el = document.getElementById('pesLightbox');
      if (el) {
        el.classList.remove('open');
        // Pause any video
        var vid = document.getElementById('pesLbVideo');
        if (vid) vid.pause();
      }
      _lb.open  = false;
      document.body.style.overflow = '';
    },

    prev: function() {
      _lb.index = (_lb.index - 1 + _lb.images.length) % _lb.images.length;
      PES_LB.render();
    },

    next: function() {
      _lb.index = (_lb.index + 1) % _lb.images.length;
      PES_LB.render();
    },

    goTo: function(i) {
      _lb.index = i;
      PES_LB.render();
    },

    render: function() {
      var src     = _lb.images[_lb.index] || '';
      var caption = _lb.captions[_lb.index] || '';
      var isVideo = typeof src === 'object' ? src.type === 'video' : /\.(mp4|webm|ogg)(\?|$)/i.test(src);
      var srcStr  = typeof src === 'object' ? src.src : src;

      var img     = document.getElementById('pesLbImg');
      var vid     = document.getElementById('pesLbVideo');
      var counter = document.getElementById('pesLbCounter');
      var cap     = document.getElementById('pesLbCaption');
      var thumbs  = document.getElementById('pesLbThumbs');
      var prev    = document.querySelector('.pes-lb-prev');
      var next    = document.querySelector('.pes-lb-next');

      if (!img) return;

      if (isVideo) {
        img.style.display = 'none';
        vid.style.display = 'block';
        vid.src = srcStr;
      } else {
        vid.style.display = 'none';
        vid.pause();
        img.style.display = 'block';
        img.src = srcStr;
        img.alt = caption;
      }

      if (counter) counter.textContent = (_lb.images.length > 1)
        ? (_lb.index + 1) + ' / ' + _lb.images.length : '';
      if (cap) cap.textContent = caption;

      // Show/hide arrows
      if (prev) prev.style.display = _lb.images.length > 1 ? '' : 'none';
      if (next) next.style.display = _lb.images.length > 1 ? '' : 'none';

      // Thumbnails
      if (thumbs) {
        thumbs.innerHTML = _lb.images.map(function(s, i) {
          var tsrc = typeof s === 'object' ? s.src : s;
          var isVid = typeof s === 'object' ? s.type === 'video' : /\.(mp4|webm|ogg)(\?|$)/i.test(tsrc);
          return '<div class="pes-lb-thumb' + (i === _lb.index ? ' active' : '') + '" onclick="PES_LB.goTo(' + i + ')">'
            + (isVid
                ? '<div style="width:100%;height:100%;background:#111;display:flex;align-items:center;justify-content:center;color:#fff;font-size:18px;">▶</div>'
                : '<img src="' + tsrc + '" alt="" draggable="false" onerror="this.src=\'images/logo.png\'">'
              )
            + '</div>';
        }).join('');
      }
    },
  };

  // ── Download Protection ────────────────────────────────

  function blockOnEl(el) {
    // Prevent right-click
    el.addEventListener('contextmenu', function(e) { e.preventDefault(); return false; });
    // Prevent drag
    el.addEventListener('dragstart', function(e) { e.preventDefault(); return false; });
    // Prevent long-press save on iOS/Android
    el.style.webkitUserDrag = 'none';
    el.style.userDrag       = 'none';
    el.style.webkitUserSelect = 'none';
    el.style.userSelect     = 'none';
    el.setAttribute('draggable', 'false');
  }

  function applyProtection() {
    var selectors = [
      'img.product-img',
      '.product-slideshow img',
      '.modal-slide img',
      '.modal-product-img',
      '.ipe-gallery img',
      '.media-thumb-img',
      '.also-bought-img',
      'img.cat-img',
      'img.cart-img',
      'img.checkout-img',
      '.pes-lb-img',
      'video.modal-video',
      '.modal-slide video',
    ];
    selectors.forEach(function(sel) {
      document.querySelectorAll(sel).forEach(blockOnEl);
    });

    // Global fallback — catch any new images added dynamically
    document.addEventListener('contextmenu', function(e) {
      var t = e.target;
      if (t && (t.tagName === 'IMG' || t.tagName === 'VIDEO')) {
        var closest = t.closest('.product-card, .product-slideshow, .modal-product-top, .inline-product-expand, .ipe-gallery, .pes-lb-stage');
        if (closest) { e.preventDefault(); return false; }
      }
    });
    document.addEventListener('dragstart', function(e) {
      var t = e.target;
      if (t && (t.tagName === 'IMG' || t.tagName === 'VIDEO')) {
        var closest = t.closest('.product-card, .product-slideshow, .modal-product-top, .inline-product-expand, .ipe-gallery, .pes-lb-stage');
        if (closest) { e.preventDefault(); return false; }
      }
    });
  }

  // ── Expand button injector ─────────────────────────────
  // Adds ⤢ button to slideshows and modals so users can open lightbox

  function addExpandButtons() {
    // Product card slideshows
    document.querySelectorAll('.product-slideshow:not([data-expand-injected])').forEach(function(ss) {
      ss.setAttribute('data-expand-injected', '1');
      var pid = ss.dataset.pid;
      var btn = document.createElement('button');
      btn.className = 'pes-expand-btn';
      btn.title = 'View fullscreen';
      btn.innerHTML = '⤢';
      btn.setAttribute('aria-label', 'Fullscreen');
      btn.onclick = function(e) {
        e.stopPropagation();
        if (pid && typeof getProducts === 'function') {
          var p = getProducts().find(function(x) { return String(x.id) === String(pid); });
          if (p) {
            var imgs = Array.isArray(p.images) && p.images.length ? p.images : (p.image ? [p.image] : []);
            if (p.video) imgs = imgs.concat([{ type:'video', src: p.video }]);
            var active = ss.querySelector('.slide.active img');
            var startIdx = 0;
            if (active) {
              var src = active.src;
              imgs.forEach(function(s, i) { if ((typeof s === 'string' ? s : s.src) === src) startIdx = i; });
            }
            PES_LB.open(imgs, startIdx, imgs.map(function() { return p.name; }));
          }
        }
      };
      ss.appendChild(btn);
    });

    // Add prev/next buttons to product card slideshows if multiple images
    document.querySelectorAll('.product-slideshow:not([data-nav-injected])').forEach(function(ss) {
      var slides = ss.querySelectorAll('.slide');
      if (slides.length <= 1) return;
      ss.setAttribute('data-nav-injected', '1');

      var prev = document.createElement('button');
      prev.innerHTML = '‹';
      prev.style.cssText = 'position:absolute;left:6px;top:50%;transform:translateY(-50%);z-index:5;background:rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.2);color:#fff;width:28px;height:28px;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;-webkit-tap-highlight-color:transparent;';
      prev.setAttribute('aria-label', 'Previous image');

      var next = document.createElement('button');
      next.innerHTML = '›';
      next.style.cssText = 'position:absolute;right:6px;top:50%;transform:translateY(-50%);z-index:5;background:rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.2);color:#fff;width:28px;height:28px;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;-webkit-tap-highlight-color:transparent;';
      next.setAttribute('aria-label', 'Next image');

      var dots = ss.querySelectorAll('.dot');
      var idx  = [0]; // use array so closure captures reference

      function goTo(n) {
        var total = slides.length;
        slides[idx[0]].classList.remove('active');
        if (dots[idx[0]]) dots[idx[0]].classList.remove('active');
        idx[0] = (n + total) % total;
        slides[idx[0]].classList.add('active');
        if (dots[idx[0]]) dots[idx[0]].classList.add('active');
      }

      prev.onclick = function(e) { e.stopPropagation(); goTo(idx[0] - 1); };
      next.onclick = function(e) { e.stopPropagation(); goTo(idx[0] + 1); };

      ss.appendChild(prev);
      ss.appendChild(next);
    });

    // Modal slideshow expand button
    var modalSs = document.getElementById('modalSlideshow');
    if (modalSs && !modalSs.dataset.expandInjected) {
      modalSs.dataset.expandInjected = '1';
      var expBtn = document.createElement('button');
      expBtn.className = 'pes-modal-expand';
      expBtn.title = 'Fullscreen';
      expBtn.innerHTML = '⤢';
      expBtn.setAttribute('aria-label', 'View fullscreen');
      expBtn.onclick = function(e) {
        e.stopPropagation();
        var slides = modalSs.querySelectorAll('.modal-slide img, .modal-slide video');
        var media = [];
        slides.forEach(function(el) {
          if (el.tagName === 'VIDEO') media.push({ type:'video', src: el.querySelector('source')?.src || el.src });
          else media.push(el.src);
        });
        var curIdx = window._modalSlideIdx || 0;
        PES_LB.open(media, curIdx);
      };
      modalSs.appendChild(expBtn);
    }
  }

  // ── MutationObserver — re-apply on dynamic DOM changes ─
  function observeDOM() {
    if (!window.MutationObserver) return;
    var observer = new MutationObserver(function(mutations) {
      var needsUpdate = mutations.some(function(m) {
        return m.addedNodes.length > 0;
      });
      if (needsUpdate) {
        applyProtection();
        addExpandButtons();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Init ───────────────────────────────────────────────
  function init() {
    injectLightboxHTML();
    applyProtection();
    addExpandButtons();
    observeDOM();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
