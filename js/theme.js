/* ═══════════════════════════════════════════════════════════════
   PARAMOUNT E-STORE — THEME SWITCHER
   Persisted to localStorage, applied to all pages
   ═══════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  const THEMES = {
    obsidian: {
      label: 'Obsidian',
      bg:    '#080808',
      nav:   '#111111',
      dot:   '#f5f5f0',
      desc:  'Classic dark'
    },
    ivory: {
      label: 'Ivory',
      bg:    '#faf8f4',
      nav:   '#f2ede4',
      dot:   '#2a2018',
      desc:  'Warm light'
    },
    slate: {
      label: 'Slate',
      bg:    '#0c0f14',
      nav:   '#141820',
      dot:   '#e8edf7',
      desc:  'Blue-grey'
    },
    emerald: {
      label: 'Emerald',
      bg:    '#060d09',
      nav:   '#0d1a10',
      dot:   '#e6f4e9',
      desc:  'Forest'
    },
    cognac: {
      label: 'Cognac',
      bg:    '#0e0906',
      nav:   '#1a1008',
      dot:   '#f8ede0',
      desc:  'Warm amber'
    },
    midnight: {
      label: 'Midnight',
      bg:    '#08060f',
      nav:   '#100e1c',
      dot:   '#eae8fa',
      desc:  'Deep purple'
    }
  };

  const FONTS = {
    classic: {
      label: 'Classic',
      display: "'Cormorant Garamond', Georgia, serif",
      body:    "'Montserrat', sans-serif",
      sample:  'Aa'
    },
    editorial: {
      label: 'Editorial',
      display: "'Playfair Display', Georgia, serif",
      body:    "'Lato', sans-serif",
      sample:  'Aa'
    },
    modern: {
      label: 'Modern',
      display: "'Raleway', sans-serif",
      body:    "'Open Sans', sans-serif",
      sample:  'Aa'
    },
    luxe: {
      label: 'Luxe',
      display: "'Libre Baskerville', Georgia, serif",
      body:    "'Nunito Sans', sans-serif",
      sample:  'Aa'
    }
  };

  // ── Read / write prefs ────────────────────────────────────────
  function getPrefs() {
    try {
      return JSON.parse(localStorage.getItem('pes_theme_prefs') || '{}');
    } catch(e) { return {}; }
  }
  function savePrefs(p) {
    localStorage.setItem('pes_theme_prefs', JSON.stringify(p));
  }

  // ── Apply everything ──────────────────────────────────────────
  function applyAll(prefs) {
    const theme   = prefs.theme   || 'obsidian';
    const font    = prefs.font    || 'classic';
    const density = prefs.density || 'default';
    const radius  = prefs.radius  || 'sharp';

    // Theme on <html>
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.setAttribute('data-density', density);
    document.documentElement.setAttribute('data-radius', radius);

    // Font injection
    const f = FONTS[font] || FONTS.classic;
    document.documentElement.style.setProperty('--font-display', f.display);
    document.documentElement.style.setProperty('--font-body', f.body);

    // Load Google Fonts if not classic
    if (font !== 'classic') {
      loadGoogleFonts(font);
    }
  }

  function loadGoogleFonts(fontKey) {
    const URLS = {
      editorial: 'https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,500;0,600;1,400&family=Lato:wght@300;400;700&display=swap',
      modern:    'https://fonts.googleapis.com/css2?family=Raleway:wght@300;400;500;600;700&family=Open+Sans:wght@300;400;600;700&display=swap',
      luxe:      'https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=Nunito+Sans:wght@300;400;600;700&display=swap'
    };
    const url = URLS[fontKey];
    if (!url) return;
    if (document.querySelector(`link[data-font="${fontKey}"]`)) return;
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    link.setAttribute('data-font', fontKey);
    document.head.appendChild(link);
  }

  // ── Init on page load ────────────────────────────────────────
  // On first visit (no saved prefs), auto-select theme based on
  // the OS/browser colour scheme preference (light vs dark).
  (function applyDefaultTheme() {
    const prefs = getPrefs();
    // Only auto-select on first ever visit — respect manual choice after that
    if (prefs.theme) { applyAll(prefs); return; }
    const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    if (prefersLight) {
      // Ivory theme for light-mode users
      prefs.theme = 'ivory';
      savePrefs(prefs);
    }
    // Dark mode users get Obsidian (default — no change needed)
    applyAll(prefs);

    // Also listen for OS theme changes during the session
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
        // Only auto-switch if the user has never manually picked a theme
        const current = getPrefs();
        const autoThemes = ['obsidian', 'ivory']; // themes we auto-assign
        if (!autoThemes.includes(current.theme)) return; // user made a custom choice
        const newTheme = e.matches ? 'ivory' : 'obsidian';
        if (current.theme === newTheme) return;
        current.theme = newTheme;
        savePrefs(current);
        applyAll(current);
        // Update swatch UI if panel is open
        const swatches = document.querySelectorAll('.theme-swatch');
        swatches.forEach(function(s) {
          s.classList.toggle('active', s.getAttribute('data-theme-key') === newTheme);
        });
      });
    }
  })();

  // ── Build & inject switcher UI ───────────────────────────────
  function buildPanel() {
    if (document.getElementById('themeTrigger')) return; // already built

    const prefs = getPrefs();
    const curTheme   = prefs.theme   || 'obsidian';
    const curFont    = prefs.font    || 'classic';
    const curDensity = prefs.density || 'default';
    const curRadius  = prefs.radius  || 'sharp';

    // Trigger button
    const trigger = document.createElement('button');
    trigger.id = 'themeTrigger';
    trigger.className = 'theme-trigger';
    trigger.title = 'Change appearance';
    trigger.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M2 12h3M19 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/></svg>`;
    trigger.onclick = () => togglePanel();

    // Panel
    const panel = document.createElement('div');
    panel.id = 'themePanel';
    panel.className = 'theme-panel';
    panel.innerHTML = `
      <div class="theme-panel-head">
        <span class="theme-panel-title">Appearance</span>
        <button class="theme-panel-close" onclick="document.getElementById('themePanel').classList.remove('open');document.getElementById('themeTrigger').classList.remove('open');">✕</button>
      </div>
      <div class="theme-panel-body">
        <div class="theme-section-label">Colour Theme</div>
        <div class="theme-swatches" id="themeSwatches"></div>

        <div class="theme-panel-divider"></div>
        <div class="theme-section-label">Typography</div>
        <div class="theme-fonts" id="themeFonts"></div>

        <div class="theme-panel-divider"></div>
        <div class="theme-section-label">Layout</div>
        <div class="theme-options-row" id="themeDensity"></div>

        <div class="theme-section-label" style="padding-top:4px;">Card Style</div>
        <div class="theme-options-row" id="themeRadius"></div>

        <div class="theme-panel-divider" style="margin-top:4px;"></div>
        <div class="theme-reset-row">
          <button class="theme-reset-btn" onclick="PESTheme.reset()">Reset to defaults</button>
        </div>
      </div>
    `;

    document.body.appendChild(trigger);
    document.body.appendChild(panel);

    // Populate swatches
    const swatchWrap = document.getElementById('themeSwatches');
    Object.entries(THEMES).forEach(([key, t]) => {
      const btn = document.createElement('button');
      btn.className = 'theme-swatch' + (key === curTheme ? ' active' : '');
      btn.title = t.desc;
      btn.setAttribute('data-theme-key', key);
      btn.innerHTML = `
        <div class="swatch-preview">
          <div class="swatch-preview-bg"  style="background:${t.bg};"></div>
          <div class="swatch-preview-nav" style="background:${t.nav};border-bottom:1px solid rgba(255,255,255,0.08);"></div>
          <div class="swatch-preview-dot" style="background:${t.dot};opacity:0.9;"></div>
        </div>
        <span class="swatch-label">${t.label}</span>
      `;
      btn.onclick = () => {
        setTheme(key);
        swatchWrap.querySelectorAll('.theme-swatch').forEach(s => s.classList.remove('active'));
        btn.classList.add('active');
      };
      swatchWrap.appendChild(btn);
    });

    // Populate fonts
    const fontWrap = document.getElementById('themeFonts');
    Object.entries(FONTS).forEach(([key, f]) => {
      const btn = document.createElement('button');
      btn.className = 'theme-font-btn' + (key === curFont ? ' active' : '');
      btn.setAttribute('data-font-key', key);
      const sampleStyle = key === 'classic' ? "font-family:'Cormorant Garamond',serif" :
                          key === 'editorial' ? "font-family:'Playfair Display',serif" :
                          key === 'modern' ? "font-family:'Raleway',sans-serif" :
                          "font-family:'Libre Baskerville',serif";
      btn.innerHTML = `<span class="font-btn-name">${f.label}</span><span class="font-btn-sample" style="${sampleStyle}">${f.sample} Paramount</span>`;
      btn.onclick = () => {
        setFont(key);
        fontWrap.querySelectorAll('.theme-font-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      };
      fontWrap.appendChild(btn);
    });

    // Density
    const densityWrap = document.getElementById('themeDensity');
    [['compact','Compact'],['default','Default'],['spacious','Airy']].forEach(([val, label]) => {
      const btn = document.createElement('button');
      btn.className = 'theme-opt-btn' + (val === curDensity ? ' active' : '');
      btn.textContent = label;
      btn.onclick = () => {
        setDensity(val);
        densityWrap.querySelectorAll('.theme-opt-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      };
      densityWrap.appendChild(btn);
    });

    // Radius
    const radiusWrap = document.getElementById('themeRadius');
    [['sharp','Sharp'],['rounded','Rounded']].forEach(([val, label]) => {
      const btn = document.createElement('button');
      btn.className = 'theme-opt-btn' + (val === curRadius ? ' active' : '');
      btn.textContent = label;
      btn.onclick = () => {
        setRadius(val);
        radiusWrap.querySelectorAll('.theme-opt-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      };
      radiusWrap.appendChild(btn);
    });
  }

  function togglePanel() {
    const panel   = document.getElementById('themePanel');
    const trigger = document.getElementById('themeTrigger');
    if (!panel) return;
    const open = panel.classList.toggle('open');
    trigger.classList.toggle('open', open);
  }

  // ── Setters ──────────────────────────────────────────────────
  function setTheme(theme) {
    const p = getPrefs();
    p.theme = theme;
    savePrefs(p);
    applyAll(p);
  }

  function setFont(font) {
    const p = getPrefs();
    p.font = font;
    savePrefs(p);
    applyAll(p);
  }

  function setDensity(density) {
    const p = getPrefs();
    p.density = density;
    savePrefs(p);
    applyAll(p);
  }

  function setRadius(radius) {
    const p = getPrefs();
    p.radius = radius;
    savePrefs(p);
    applyAll(p);
  }

  function reset() {
    localStorage.removeItem('pes_theme_prefs');
    applyAll({});
    // Refresh panel UI
    const panel = document.getElementById('themePanel');
    if (panel) { panel.remove(); }
    const trigger = document.getElementById('themeTrigger');
    if (trigger) { trigger.remove(); }
    buildPanel();
  }

  // ── Public API ───────────────────────────────────────────────
  window.PESTheme = { setTheme, setFont, setDensity, setRadius, reset };

  // ── Build panel after DOM ready ──────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildPanel);
  } else {
    buildPanel();
  }

  // Close panel on click outside
  document.addEventListener('click', function(e) {
    const panel   = document.getElementById('themePanel');
    const trigger = document.getElementById('themeTrigger');
    if (panel && panel.classList.contains('open')) {
      if (!panel.contains(e.target) && !trigger.contains(e.target)) {
        panel.classList.remove('open');
        trigger.classList.remove('open');
      }
    }
  }, true);

})();
