/* =============================================
   PARAMOUNT E-STORE — STORE JS  (popup edition)
   ============================================= */

let cart = JSON.parse(localStorage.getItem('pes_cart') || '[]');
let shopActiveFilter = 'All';
let searchActiveCat  = 'All';

// ─── INIT ────────────────────────────────────


// ── INLINE PRODUCT EXPAND (homepage featured grid) ──────────
function expandProductInline(id, cardEl) {
  // If already expanded, close it
  const existing = document.getElementById('inlineExpand-' + id);
  if (existing) {
    existing.classList.remove('ipe-open');
    setTimeout(() => existing.remove(), 300);
    cardEl.classList.remove('ipe-active');
    return;
  }
  // Close any other open expand
  document.querySelectorAll('.inline-product-expand').forEach(el => {
    el.classList.remove('ipe-open');
    setTimeout(() => el.remove(), 300);
  });
  document.querySelectorAll('.product-card').forEach(el => el.classList.remove('ipe-active'));

  const p = getProducts().find(x => x.id === id);
  if (!p) return;
  const stockLabel = {'in-stock':'In Stock','limited':'Limited Stock','out-of-stock':'Out of Stock'}[p.stock]||'In Stock';
  const disabled = p.stock === 'out-of-stock';
  const imgs = Array.isArray(p.images)&&p.images.length ? p.images : (p.image?[p.image]:[]);
  const serial = typeof getProductSerial === 'function' ? getProductSerial(p) : '';
  const qty = p.stockQty !== undefined ? p.stockQty : null;
  let qtyHtml = '';
  if (qty !== null) {
    if (qty === 0) qtyHtml = `<span class="product-stock-qty out-of-stock">0 left</span>`;
    else if (qty <= 5) qtyHtml = `<span class="product-stock-qty limited">Only ${qty} left</span>`;
    else qtyHtml = `<span class="product-stock-qty in-stock">${qty} in stock</span>`;
  }

  // Build image HTML — same as modal
  let imgHtml = '';
  if (imgs.length > 1) {
    imgHtml = `<div class="ipe-gallery">
      <div class="ipe-gallery-main" id="ipeMain-${id}">
        <img src="${imgs[0]}" alt="${p.name}" onerror="this.src='images/logo.png'" class="ipe-img"/>
      </div>
      <div class="ipe-gallery-thumbs">
        ${imgs.map((src,si)=>`<div class="ipe-thumb ${si===0?'active':''}" onclick="setIpeImg('${src}','ipeMain-${id}',this)">
          <img src="${src}" alt="${p.name}" onerror="this.src='images/logo.png'"/>
        </div>`).join('')}
      </div>
    </div>`;
  } else {
    imgHtml = `<div class="ipe-single-img-wrap"><img src="${imgs[0]||'images/logo.png'}" alt="${p.name}" class="ipe-img" onerror="this.src='images/logo.png'"/></div>`;
  }

  const expand = document.createElement('div');
  expand.className = 'inline-product-expand';
  expand.id = 'inlineExpand-' + id;
  expand.innerHTML = `
    <button class="ipe-close" onclick="expandProductInline(${id}, document.querySelector('.ipe-active'))">✕</button>
    <div class="ipe-inner">
      <div class="ipe-media">${imgHtml}</div>
      <div class="ipe-info">
        <div class="ipe-meta">${p.category} ${serial ? `<span style="color:var(--gray);font-size:9px;">· ${serial}</span>` : ''}</div>
        <div class="ipe-name">${p.name}</div>
        <div class="ipe-price">${formatPrice(p.price)}</div>
        <div class="modal-product-stock ${p.stock||'in-stock'}" style="font-size:11px;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:8px;">${stockLabel}</div>
        ${qtyHtml ? `<div style="margin:8px 0;">${qtyHtml}</div>` : ''}
        <div class="modal-divider" style="margin:20px 0;"></div>
        <p class="ipe-desc">${p.description||''}</p>
        <div class="ipe-actions">
          <button class="modal-add-btn" ${disabled?'disabled':''} onclick="addToCart(${p.id}); expandProductInline(${id}, document.querySelector('.ipe-active'))">
            ${disabled?'Out of Stock':'Add to Cart'}
          </button>
          <button class="modal-share-btn" onclick="openProductModal(${id}); shareProduct(${id})" style="white-space:nowrap;">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:5px;"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>Share
          </button>
        </div>
      </div>
    </div>`;

  // Insert after the card's row in the grid
  const grid = cardEl.closest('.featured-grid');
  if (grid) {
    grid.appendChild(expand);
  } else {
    cardEl.insertAdjacentElement('afterend', expand);
  }
  cardEl.classList.add('ipe-active');
  requestAnimationFrame(() => expand.classList.add('ipe-open'));
  expand.scrollIntoView({ behavior:'smooth', block:'nearest' });
}

function setIpeImg(src, containerId, thumbEl) {
  const main = document.getElementById(containerId);
  if (main) { const img = main.querySelector('img'); if (img) img.src = src; }
  const wrap = thumbEl?.closest('.ipe-gallery-thumbs');
  if (wrap) wrap.querySelectorAll('.ipe-thumb').forEach(t => t.classList.remove('active'));
  if (thumbEl) thumbEl.classList.add('active');
}

// ── NIGERIAN CITY COORDINATE MAP ─────────────────────
// Used to resolve delivery address into GPS coords for shipment tracking
const NG_CITIES = {
  'lagos':          { city:'Lagos',         state:'Lagos',         lat:6.5244,  lng:3.3792,  code:'LOS' },
  'abuja':          { city:'Abuja',          state:'FCT',           lat:9.0579,  lng:7.4951,  code:'ABJ' },
  'fct':            { city:'Abuja',          state:'FCT',           lat:9.0579,  lng:7.4951,  code:'ABJ' },
  'kano':           { city:'Kano',           state:'Kano',          lat:12.0022, lng:8.5920,  code:'KAN' },
  'ibadan':         { city:'Ibadan',         state:'Oyo',           lat:7.3775,  lng:3.9470,  code:'IBA' },
  'port harcourt':  { city:'Port Harcourt',  state:'Rivers',        lat:4.8156,  lng:7.0498,  code:'PHC' },
  'ph':             { city:'Port Harcourt',  state:'Rivers',        lat:4.8156,  lng:7.0498,  code:'PHC' },
  'benin':          { city:'Benin City',     state:'Edo',           lat:6.3350,  lng:5.6037,  code:'BEN' },
  'benin city':     { city:'Benin City',     state:'Edo',           lat:6.3350,  lng:5.6037,  code:'BEN' },
  'kaduna':         { city:'Kaduna',         state:'Kaduna',        lat:10.5105, lng:7.4165,  code:'KAD' },
  'jos':            { city:'Jos',            state:'Plateau',       lat:9.8965,  lng:8.8583,  code:'JOS' },
  'enugu':          { city:'Enugu',          state:'Enugu',         lat:6.4584,  lng:7.5464,  code:'ENU' },
  'onitsha':        { city:'Onitsha',        state:'Anambra',       lat:6.1429,  lng:6.7870,  code:'ONI' },
  'aba':            { city:'Aba',            state:'Abia',          lat:5.1066,  lng:7.3670,  code:'ABA' },
  'warri':          { city:'Warri',          state:'Delta',         lat:5.5167,  lng:5.7500,  code:'WAR' },
  'uyo':            { city:'Uyo',            state:'Akwa Ibom',     lat:5.0377,  lng:7.9128,  code:'UYO' },
  'calabar':        { city:'Calabar',        state:'Cross River',   lat:4.9517,  lng:8.3220,  code:'CAL' },
  'owerri':         { city:'Owerri',         state:'Imo',           lat:5.4836,  lng:7.0333,  code:'OWE' },
  'asaba':          { city:'Asaba',          state:'Delta',         lat:6.1939,  lng:6.7382,  code:'ASA' },
  'akure':          { city:'Akure',          state:'Ondo',          lat:7.2526,  lng:5.1926,  code:'AKR' },
  'osogbo':         { city:'Osogbo',         state:'Osun',          lat:7.7667,  lng:4.5500,  code:'OSO' },
  'ilorin':         { city:'Ilorin',         state:'Kwara',         lat:8.4966,  lng:4.5426,  code:'ILO' },
  'sokoto':         { city:'Sokoto',         state:'Sokoto',        lat:13.0059, lng:5.2476,  code:'SOK' },
  'maiduguri':      { city:'Maiduguri',      state:'Borno',         lat:11.8333, lng:13.1500, code:'MAI' },
  'yola':           { city:'Yola',           state:'Adamawa',       lat:9.2035,  lng:12.4954, code:'YOL' },
  'makurdi':        { city:'Makurdi',        state:'Benue',         lat:7.7306,  lng:8.5361,  code:'MAK' },
  'lafia':          { city:'Lafia',          state:'Nasarawa',      lat:8.4840,  lng:8.5158,  code:'LAF' },
  'minna':          { city:'Minna',          state:'Niger',         lat:9.6139,  lng:6.5569,  code:'MIN' },
  'lokoja':         { city:'Lokoja',         state:'Kogi',          lat:7.7936,  lng:6.7378,  code:'LOK' },
  'abeokuta':       { city:'Abeokuta',       state:'Ogun',          lat:7.1475,  lng:3.3619,  code:'ABE' },
  'sagamu':         { city:'Sagamu',         state:'Ogun',          lat:6.8388,  lng:3.6458,  code:'SAG' },
  'ikeja':          { city:'Ikeja',          state:'Lagos',         lat:6.5954,  lng:3.3378,  code:'IKE' },
  'victoria island':{ city:'Victoria Island',state:'Lagos',         lat:6.4281,  lng:3.4219,  code:'VIS' },
  'lekki':          { city:'Lekki',          state:'Lagos',         lat:6.4350,  lng:3.5231,  code:'LEK' },
  'ajah':           { city:'Ajah',           state:'Lagos',         lat:6.4667,  lng:3.5833,  code:'AJA' },
};

function resolveDeliveryLocation(address) {
  if (!address) return NG_CITIES['uyo']; // default fallback
  const lower = address.toLowerCase();
  for (const [key, val] of Object.entries(NG_CITIES)) {
    if (lower.includes(key)) return val;
  }
  return null; // couldn't resolve
}

function generateTrackingId(destCode, orderRef) {
  // Format: PES-TRK-{DESTCODE}-{RANDOM4}
  // e.g. PES-TRK-ABJ-4827
  const rand = Math.floor(1000 + Math.random() * 9000);
  if (destCode) return 'PES-TRK-' + destCode + '-' + rand;
  // Fallback: use last 4 digits of order ref timestamp
  const ts = String(Date.now()).slice(-4);
  return 'PES-TRK-' + ts;
}

function createShipmentFromOrder(order) {
  const origin = NG_CITIES['uyo']; // all orders ship from Uyo, Akwa Ibom hub
  const dest   = resolveDeliveryLocation(order.address);
  const destInfo = dest || { city: order.address || 'Nigeria', state: 'Nigeria', lat: 9.0579, lng: 7.4951, code: 'NG' };
  const trackingId = generateTrackingId(destInfo.code, order.id);
  const isInternational = !dest; // if we couldn't resolve an NG city, treat as international
  const now = new Date();
  const dispatchDate = new Date(now.getTime() + 86400000); // dispatch next day
  const estDelivery  = new Date(now.getTime() + (isInternational ? 7 : 4) * 86400000);
  const fmt = d => d.toISOString().split('T')[0];
  const fmtTime = d => d.toISOString().replace('T',' ').slice(0,16);

  const totalWeight = order.items.reduce((a,b) => a + (parseFloat(b.weight)||1) * b.qty, 0);

  const shipment = {
    id:              trackingId,
    orderId:         order.id,
    customer:        order.customer,
    email:           order.email,
    phone:           order.phone,
    product:         order.items.map(i => i.name + ' ×' + i.qty).join(', ').substring(0, 80),
    origin:          { city: origin.city, country: 'Nigeria', lat: origin.lat, lng: origin.lng },
    destination:     { city: destInfo.city, country: isInternational ? 'International' : 'Nigeria', lat: destInfo.lat, lng: destInfo.lng },
    currentLocation: { city: origin.city, country: 'Nigeria', lat: origin.lat, lng: origin.lng },
    status:          'Order Placed',
    statusIndex:     0,
    carrier:         'Paramount Logistics',
    estimatedDelivery: fmt(estDelivery),
    dispatchDate:    fmt(dispatchDate),
    type:            isInternational ? 'international' : 'domestic',
    weight:          totalWeight > 0 ? totalWeight.toFixed(1) + 'kg' : 'TBC',
    value:           order.total,
    address:         order.address,
    history: [
      { status: 'Order Placed', time: fmtTime(now), location: 'Online', note: 'Payment confirmed. Order received and logged.' }
    ]
  };
  return shipment;
}


// ══════════════════════════════════════════════════════
//  LIVE EXCHANGE RATE ENGINE
//  Auto-fetches NGN rates against all configured currencies
//  No API key needed — uses free public APIs with fallbacks
//  Refreshes on page load + every 4 hours
// ══════════════════════════════════════════════════════

const _RATE_CACHE_KEY   = 'pes_fx_rates';
const _RATE_TS_KEY      = 'pes_fx_rates_ts';
const _RATE_TTL_MS      = 4 * 60 * 60 * 1000; // 4 hours
const _RATE_FALLBACKS   = { USD:1600, GBP:2050, EUR:1750, CAD:1180, AUD:1040, GHS:11, KES:12, ZAR:85, XOF:1.0 };

// ── Fetch from multiple free APIs with fallback chain ──
async function _fetchLiveRates() {
  const sources = [
    // 1. Fawaz Ahmed currency API — completely free, no key, daily updates
    async () => {
      const r = await fetch('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/ngn.min.json');
      const d = await r.json();
      if (!d.ngn) throw new Error('No ngn key');
      // d.ngn = { usd: 0.000625, gbp: 0.000488, ... }
      const rates = {};
      for (const [cur, val] of Object.entries(d.ngn)) {
        if (val && val > 0) rates[cur.toUpperCase()] = Math.round(1 / val);
      }
      return rates; // rates[USD] = how many NGN per 1 USD
    },
    // 2. Open Exchange Rates (free endpoint, NGN base)
    async () => {
      const r = await fetch('https://open.er-api.com/v6/latest/USD');
      const d = await r.json();
      if (d.result !== 'success') throw new Error('ER-API failed');
      // Convert: d.rates[NGN] = NGN per 1 USD
      const usdToNgn = d.rates['NGN'];
      if (!usdToNgn) throw new Error('No NGN rate');
      const rates = { USD: Math.round(usdToNgn) };
      for (const [cur, val] of Object.entries(d.rates)) {
        if (val && val > 0 && _RATE_FALLBACKS[cur] !== undefined) {
          rates[cur] = Math.round(usdToNgn / val);
        }
      }
      return rates;
    },
    // 3. ExchangeRate-API free tier
    async () => {
      const r = await fetch('https://api.exchangerate-api.com/v4/latest/NGN');
      const d = await r.json();
      if (!d.rates) throw new Error('No rates');
      const rates = {};
      for (const [cur, val] of Object.entries(d.rates)) {
        if (val && val > 0 && _RATE_FALLBACKS[cur] !== undefined) {
          rates[cur] = Math.round(1 / val);
        }
      }
      return rates;
    }
  ];

  for (const source of sources) {
    try {
      const rates = await source();
      if (rates && rates.USD && rates.USD > 100) { // sanity check
        return rates;
      }
    } catch (e) {
      // try next source
    }
  }
  return null; // all failed
}

async function refreshExchangeRates(force) {
  const now    = Date.now();
  const lastTs = parseInt(localStorage.getItem(_RATE_TS_KEY) || '0');
  if (!force && (now - lastTs) < _RATE_TTL_MS) return; // still fresh

  const rates = await _fetchLiveRates();
  if (rates && Object.keys(rates).length > 0) {
    localStorage.setItem(_RATE_CACHE_KEY, JSON.stringify(rates));
    localStorage.setItem(_RATE_TS_KEY,    String(now));

    // Auto-update Flutterwave currency rate if stored
    const flwCur = localStorage.getItem('pes_flutterwave_currency') || 'NGN';
    if (flwCur !== 'NGN' && rates[flwCur]) {
      localStorage.setItem('pes_flutterwave_fx_rate', String(rates[flwCur]));
    }
    console.log('[PES FX] Rates updated:', Object.keys(rates).join(', '), '@ NGN');
    return rates;
  }
  return null;
}

function getLiveRate(currency) {
  // Returns how many NGN = 1 of `currency`
  try {
    const cached = JSON.parse(localStorage.getItem(_RATE_CACHE_KEY) || '{}');
    return cached[currency.toUpperCase()] || _RATE_FALLBACKS[currency.toUpperCase()] || 1600;
  } catch {
    return _RATE_FALLBACKS[currency.toUpperCase()] || 1600;
  }
}

function getRatesTimestamp() {
  const ts = parseInt(localStorage.getItem(_RATE_TS_KEY) || '0');
  if (!ts) return null;
  return new Date(ts);
}

// ── Auto-refresh on DOMContentLoaded (after other inits) ──
// Called inside DOMContentLoaded below

document.addEventListener('DOMContentLoaded', () => {
  renderFeaturedInline();
  renderCategoryStrip();
  updateCartUI();
  buildSearchCatFilters();
  initHeroSearch();
  handleShareLinkParam();
  // Kick off exchange rate refresh (non-blocking)
  refreshExchangeRates(false);
  // Background refresh every 4 hours
  setInterval(() => refreshExchangeRates(true), 4 * 60 * 60 * 1000);
  // Handle cross-page popup opens (footer links, tracking page nav, etc.)
  const pendingOpen = sessionStorage.getItem('pes_open');
  if (pendingOpen) {
    sessionStorage.removeItem('pes_open');
    setTimeout(() => {
      if (pendingOpen === 'contact'  && typeof openContactPopup  === 'function') { openContactPopup(); return; }
      if (pendingOpen === 'shop'     && typeof openShopPopup     === 'function') { openShopPopup(); return; }
      if (pendingOpen === 'featured' && typeof openFeaturedPopup === 'function') { openFeaturedPopup(); return; }
      if (pendingOpen.startsWith('shop:') && typeof openShopPopupFiltered === 'function') {
        openShopPopupFiltered(pendingOpen.slice(5)); return;
      }
    }, 400);
  }
});

// ─── HELPERS ─────────────────────────────────
function scrollToSection(id){ const el=document.getElementById(id); if(el) el.scrollIntoView({behavior:'smooth'}); }

function pImg(src, alt, cls){
  cls = cls||'prod-img';
  const s = (src&&(src.includes('/')||src.includes('.'))) ? src : 'images/logo.png';
  return `<img src="${s}" alt="${alt||''}" class="${cls}" loading="lazy" onerror="this.src='images/logo.png'"/>`;
}
function noOp(){}

function openPopup(overlayId, popupId){
  document.getElementById(overlayId).classList.add('open');
  document.getElementById(popupId).classList.add('open');
  document.body.style.overflow='hidden';
}
function closePopup(overlayId, popupId){
  document.getElementById(overlayId).classList.remove('open');
  document.getElementById(popupId).classList.remove('open');
  document.body.style.overflow='';
}

// ─── MOBILE NAV ──────────────────────────────
function toggleMobileNav(){
  document.getElementById('mobDrawer').classList.toggle('open');
  document.getElementById('mobOverlay').classList.toggle('open');
  document.body.style.overflow = document.getElementById('mobDrawer').classList.contains('open') ? 'hidden' : '';
}

function runMobSearch(){
  const q = document.getElementById('mobSearchInput').value.trim().toLowerCase();
  const out = document.getElementById('mobSearchResults');
  if(!q){ out.innerHTML=''; return; }
  const res = getProducts().filter(p=>
    p.name.toLowerCase().includes(q)||p.category.toLowerCase().includes(q)||p.description.toLowerCase().includes(q)
  ).slice(0,5);
  if(!res.length){ out.innerHTML=`<div class="mob-search-none">No products found</div>`; return; }
  out.innerHTML = res.map(p=>`
    <div class="mob-search-item" onclick="toggleMobileNav(); openProductModal(${p.id})">
      <div class="mob-search-img">${pImg(p.image,p.name,'mob-sr-img')}</div>
      <div class="mob-search-info"><div class="mob-search-name">${p.name}</div><div class="mob-search-price">${formatPrice(p.price)}</div></div>
    </div>
  `).join('');
}

// ─── SEARCH POPUP ────────────────────────────
function openSearchPopup(){
  openPopup('searchOverlay','searchPopup');
  setTimeout(()=>{ const el=document.getElementById('mainSearchInput'); if(el) el.focus(); },200);
}
function closeSearchPopup(){ closePopup('searchOverlay','searchPopup'); }

function buildSearchCatFilters(){
  const wrap = document.getElementById('searchCatFilters');
  if(!wrap) return;
  const cats = ['All',...getCategories().map(c=>c.name)];
  wrap.innerHTML = cats.map(c=>`
    <button class="search-cat-btn ${c===searchActiveCat?'active':''}" onclick="setSearchCat('${c.replace(/'/g,"\\'")}')">
      ${c}
    </button>
  `).join('');
}

function setSearchCat(cat){
  searchActiveCat = cat;
  buildSearchCatFilters();
  runSearch();
}

function runSearch(){
  const q   = document.getElementById('mainSearchInput').value.trim().toLowerCase();
  const clr = document.getElementById('searchClear');
  if(clr) clr.style.display = q ? 'flex' : 'none';

  const wrap = document.getElementById('searchResultsWrap');

  if(!q){
    wrap.innerHTML=`<div class="search-placeholder"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><p>Start typing to search products</p></div>`;
    return;
  }

  let products = getProducts().filter(p=>
    p.name.toLowerCase().includes(q)||p.description.toLowerCase().includes(q)||p.category.toLowerCase().includes(q)
  );
  if(searchActiveCat!=='All') products = products.filter(p=>p.category===searchActiveCat);

  if(!products.length){
    wrap.innerHTML=`<div class="search-none"><p>No products found for "<strong>${q}</strong>"</p><p class="search-none-sub">Try a different keyword or browse categories.</p></div>`;
    return;
  }

  wrap.innerHTML=`
    <div class="search-count">${products.length} result${products.length!==1?'s':''} for "<strong>${q}</strong>"</div>
    <div class="search-results-grid">${products.map(p=>searchCard(p)).join('')}</div>
  `;
}

function searchCard(p){
  const stockLabel={'in-stock':'In Stock','limited':'Limited','out-of-stock':'Out of Stock'}[p.stock]||'In Stock';
  const disabled=p.stock==='out-of-stock';
  return `
    <div class="search-result-card" onclick="closeSearchPopup(); openProductModal(${p.id})">
      <div class="src-img-wrap">${pImg(p.image,p.name,'src-img')}</div>
      <div class="src-info">
        ${p.badge?`<span class="src-badge">${p.badge}</span>`:''}
        <div class="src-cat">${p.category}</div>
        <div class="src-name">${p.name}</div>
        <div class="src-price">${formatPrice(p.price)}</div>
        <div class="src-stock ${p.stock}">${stockLabel}</div>
      </div>
      <div class="src-actions" onclick="event.stopPropagation()">
        <button class="btn-add-cart" ${disabled?'disabled':''} onclick="addToCart(${p.id}); closeSearchPopup()">
          ${disabled?'Out of Stock':'Add to Cart'}
        </button>
      </div>
    </div>
  `;
}

function clearSearch(){
  document.getElementById('mainSearchInput').value='';
  document.getElementById('searchClear').style.display='none';
  runSearch();
  document.getElementById('mainSearchInput').focus();
}

// ─── FEATURED POPUP ──────────────────────────
function openFeaturedPopup(){
  const grid=document.getElementById('featuredPopupGrid');
  const items=getProducts().filter(p=>p.featured);
  grid.innerHTML=items.length ? items.map((p,i)=>popupProductCard(p,i,'closeFeaturedPopup')).join('') :
    `<p style="color:var(--gray);padding:40px;text-align:center;">No featured products yet.</p>`;
  openPopup('featuredOverlay','featuredPopup');
  setTimeout(initSlideshows, 100);
}
function closeFeaturedPopup(){ closePopup('featuredOverlay','featuredPopup'); }

// ─── SHOP POPUP ───────────────────────────────
function openShopPopup(){ shopActiveFilter='All'; _buildShopPopup(); }
function openShopPopupFiltered(cat){
  const cats = getCategories();
  const targetCat = cats.find(c => c.name === cat);
  if (targetCat && targetCat.ageRestricted) {
    if (typeof isAgeVerified !== 'function' || !isAgeVerified()) {
      openAgeVerificationModal(cat);
      return;
    }
  }
  shopActiveFilter = cat;
  _buildShopPopup();
}

function _buildShopPopup(){
  const verified   = typeof isAgeVerified === 'function' && isAgeVerified();
  const allCatObjs = getCategories().sort((a,b) => a.name.localeCompare(b.name));
  const bar        = document.getElementById('shopFilterBar');
  const filterCats = ['All', ...allCatObjs.map(c => c.name)];
  bar.innerHTML = filterCats.map(c => {
    const catObj     = allCatObjs.find(x => x.name === c);
    const restricted = catObj && catObj.ageRestricted;
    const label      = restricted ? (verified ? '🔞 ' + c : '🔒 ' + c) : c;
    const onclick    = restricted && !verified
      ? 'openAgeVerificationModal(\'' + c + '\')'
      : "setShopFilter('" + c.replace(/'/g, "\'") + "')";
    return '<button class="filter-btn ' + (c === shopActiveFilter ? 'active' : '') +
      (restricted ? ' filter-btn-age-restricted' : '') + '" onclick="' + onclick + '">' + label + '</button>';
  }).join('');
  renderShopPopup();
  document.getElementById('shopPopupTitle').textContent = shopActiveFilter === 'All' ? 'All Products' : shopActiveFilter;
  openPopup('shopOverlay','shopPopup');
}

function setShopFilter(cat){
  const cats = getCategories();
  const targetCat = cats.find(c => c.name === cat);
  if (targetCat && targetCat.ageRestricted) {
    if (typeof isAgeVerified !== 'function' || !isAgeVerified()) {
      openAgeVerificationModal(cat);
      return;
    }
  }
  shopActiveFilter = cat;
  document.getElementById('shopPopupTitle').textContent = cat==='All' ? 'All Products' : cat;
  document.querySelectorAll('#shopFilterBar .filter-btn').forEach(b => {
    b.classList.toggle('active', b.textContent.trim().replace(/^[\uD83D\uDD1E\uD83D\uDD12]\s*/, '') === cat);
  });
  renderShopPopup();
}

function renderShopPopup(){
  const _ss = document.getElementById('shopInlineSearch');
  const q = (_ss ? _ss.value : '').toLowerCase();
  const verified = typeof isAgeVerified === 'function' && isAgeVerified();
  const ageCats  = getCategories().filter(c => c.ageRestricted).map(c => c.name);
  let prods = getProducts();
  if (!verified) prods = prods.filter(p => !ageCats.includes(p.category));
  if (shopActiveFilter !== 'All') prods = prods.filter(p => p.category === shopActiveFilter);
  if (q) prods = prods.filter(p => p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q));
  const grid=document.getElementById('shopPopupGrid');
  if(!prods.length){
    grid.innerHTML=`<div class="popup-empty">No products found. <button onclick="setShopFilter('All')" class="popup-empty-link">Clear filter</button></div>`;
    return;
  }
  grid.innerHTML=prods.map((p,i)=>popupProductCard(p,i,'closeShopPopup')).join('');
  setTimeout(initSlideshows, 100);
}
function closeShopPopup(){
  closePopup('shopOverlay','shopPopup');
  if (shopActiveFilter !== 'All') {
    const ageCats = getCategories().filter(c => c.ageRestricted).map(c => c.name);
    if (ageCats.includes(shopActiveFilter)) {
      if (typeof revokeSessionAgeAccess === 'function') revokeSessionAgeAccess();
    }
  }
  shopActiveFilter = 'All';
}

// ─── CATEGORIES POPUP ─────────────────────────
function openCategoriesPopup(){
  const cats  = getCategories();
  const prods = getProducts();
  const sorted = [...cats].sort((a,b) => {
    if (a.ageRestricted && !b.ageRestricted) return 1;
    if (!a.ageRestricted && b.ageRestricted) return -1;
    return a.name.localeCompare(b.name);
  });
  document.getElementById('popupCatsGrid').innerHTML = sorted.map(cat => {
    if (cat.ageRestricted) {
      const verified  = typeof isAgeVerified === 'function' && isAgeVerified();
      const safeName  = cat.name.replace(/'/g, "\'");
      return '<div class="popup-cat-card popup-cat-age-restricted" onclick="closeCategoriesPopup(); handleAdultCategoryClick(event,\'' + safeName + '\')">' +
        '<div class="popup-cat-img-wrap popup-cat-lock">' + (verified ? '🔞' : '🔒') + '</div>' +
        '<div class="popup-cat-name">' + cat.name + '</div>' +
        '<div class="popup-cat-count">' + (verified ? ('Verified — ' + (typeof getSessionMinutesRemaining === 'function' && getSessionMinutesRemaining() > 0 ? getSessionMinutesRemaining() + ' min remaining' : '18+')) : '18+ Age Verified Only') + '</div>' +
        '<div class="popup-cat-arrow">→</div></div>';
    }
    const count    = prods.filter(p => p.category === cat.name).length;
    const safeName = cat.name.replace(/'/g, "\'");
    return '<div class="popup-cat-card" onclick="closeCategoriesPopup(); openShopPopupFiltered(\'' + safeName + '\')">' +
      '<div class="popup-cat-img-wrap">' + pImg(cat.image, cat.name, 'popup-cat-img') + '</div>' +
      '<div class="popup-cat-name">' + cat.name + '</div>' +
      '<div class="popup-cat-count">' + count + ' product' + (count !== 1 ? 's' : '') + '</div>' +
      '<div class="popup-cat-arrow">→</div></div>';
  }).join('');
  openPopup('catsOverlay','catsPopup');
}
function closeCategoriesPopup(){
  closePopup('catsOverlay','catsPopup');
  if (typeof revokeSessionAgeAccess === 'function') revokeSessionAgeAccess();
}

// ─── CONTACT POPUP ────────────────────────────
function openContactPopup(){ openPopup('contactOverlay','contactPopup'); }
function closeContactPopup(){ closePopup('contactOverlay','contactPopup'); }
function sendContact(){
  var name  = document.getElementById('ctName').value.trim();
  var email = document.getElementById('ctEmail').value.trim();
  var msg   = document.getElementById('ctMessage').value.trim();
  if (!name || !email || !msg) { showToast('Please fill in all fields'); return; }

  if (typeof pesVerifying !== 'function') {
    document.getElementById('ctName').value=''; document.getElementById('ctEmail').value=''; document.getElementById('ctMessage').value='';
    closeContactPopup(); showToast('Message sent! We will get back to you soon.'); return;
  }

  closeContactPopup();
  pesVerifying('Sending Your Message…', function(done) {
    // message is client-side only — no server call needed
    done('Message Sent! 📬', "Thanks, " + name + "! We'll get back to you soon.", null);
  }, { icon: '📬', minMs: 2500, maxMs: 4000 });

  document.getElementById('ctName').value='';
  document.getElementById('ctEmail').value='';
  document.getElementById('ctMessage').value='';
}

// ─── SHARED PRODUCT CARD (for popups) ─────────
// ─── INLINE FEATURED (homepage) ──────────────
function renderFeaturedInline(){
  const grid = document.getElementById('featuredGrid');
  if (!grid) return;
  const verified = typeof isAgeVerified === 'function' && isAgeVerified();
  const ageCats  = getCategories().filter(c => c.ageRestricted).map(c => c.name);
  const allProds = getProducts();
  let items = allProds.filter(p => p.featured && (verified || !ageCats.includes(p.category))).slice(0, 6);
  if (!items.length) {
    items = allProds.filter(p => verified || !ageCats.includes(p.category)).slice(0, 6);
  }
  if (!items.length) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:60px 20px;color:#666;font-size:13px;letter-spacing:0.1em;">No products yet. Add products in the admin panel.</div>';
    return;
  }
  grid.innerHTML = items.map((p, i) => homepageProductCard(p, i)).join('');
  setTimeout(initSlideshows, 100);
}

function renderCategoryStrip(){
  const grid    = document.getElementById('catGrid');
  if (!grid) return;
  const prods   = getProducts();
  const allCats = getCategories();
  if (!allCats || !allCats.length) { setTimeout(renderCategoryStrip, 300); return; }
  const sorted  = [...allCats].sort((a,b) => {
    if (a.ageRestricted && !b.ageRestricted) return 1;
    if (!a.ageRestricted && b.ageRestricted) return -1;
    return a.name.localeCompare(b.name);
  });
  const withProds  = sorted.filter(cat => cat.ageRestricted || prods.some(p => p.category === cat.name));
  const show       = withProds.slice(0, 3);
  const moreCount  = withProds.length - 3;

  const cards = show.map(cat => {
    if (cat.ageRestricted) {
      const verified = typeof isAgeVerified === 'function' && isAgeVerified();
      const safeName = cat.name.replace(/'/g, "\'");
      return '<div class="cat-item cat-age-restricted" onclick="handleAdultCategoryClick(event,\'' + safeName + '\')">' +
        '<div class="cat-item-img-wrap cat-lock-wrap"><span class="cat-lock-icon">' + (verified ? '🔞' : '🔒') + '</span></div>' +
        '<div class="cat-item-name">' + cat.name + '</div>' +
        '<div class="cat-item-count">' + (verified ? ('🔓 ' + (typeof getSessionMinutesRemaining === 'function' && getSessionMinutesRemaining() > 0 ? getSessionMinutesRemaining() + ' min left' : 'Verified')) : '18+ Only') + '</div>' +
        '</div>';
    }
    const count    = prods.filter(p => p.category === cat.name).length;
    const safeName = cat.name.replace(/'/g, "\'");
    return '<div class="cat-item" onclick="openShopPopupFiltered(\'' + safeName + '\')">' +
      '<div class="cat-item-img-wrap">' + pImg(cat.image, cat.name, 'cat-img') + '</div>' +
      '<div class="cat-item-name">' + cat.name + '</div>' +
      '<div class="cat-item-count">' + count + ' product' + (count !== 1 ? 's' : '') + '</div>' +
      '</div>';
  }).join('');

  const seeMore = moreCount > 0
    ? '<div class="cat-item cat-see-more" onclick="openCategoriesPopup()">' +
        '<div class="cat-item-img-wrap cat-see-more-icon">' +
          '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">' +
            '<circle cx="5" cy="12" r="1.5" fill="currentColor"/>' +
            '<circle cx="12" cy="12" r="1.5" fill="currentColor"/>' +
            '<circle cx="19" cy="12" r="1.5" fill="currentColor"/>' +
          '</svg></div>' +
        '<div class="cat-item-name">See More</div>' +
        '<div class="cat-item-count">' + moreCount + ' more categor' + (moreCount !== 1 ? 'ies' : 'y') + '</div>' +
      '</div>'
    : '';

  grid.innerHTML = cards + seeMore;
}

function handleAdultCategoryClick(event, catName) {
  event.preventDefault();
  event.stopPropagation();
  if (typeof isAgeVerified === 'function' && isAgeVerified()) {
    openShopPopupFiltered(catName);
  } else {
    openAgeVerificationModal(catName);
  }
}


function setGalleryImg(src, thumbEl){
  const main=document.getElementById('galleryMain');
  if(main) main.innerHTML=`<img src="${src}" class="modal-product-img" onerror="this.src='images/logo.png'" />`;
  document.querySelectorAll('.gallery-thumb').forEach(t=>t.classList.remove('active'));
  if(thumbEl) thumbEl.classList.add('active');
}

// ─── SHARE LINKS ─────────────────────────────
function getShareLink(p) {
  const serial = getProductSerial(p);
  const base   = window.location.origin + window.location.pathname;
  return base + '?p=' + encodeURIComponent(serial);
}

function shareProduct(id) {
  const p = getProducts().find(x => x.id === id);
  if (!p) return;
  const serial = getProductSerial(p);
  const link   = getShareLink(p);
  const waText = encodeURIComponent(`🛒 *${p.name}*\n${formatPrice(p.price)}\n\nView & order here:\n${link}`);
  const xText  = encodeURIComponent(`Check out ${p.name} — ${formatPrice(p.price)} on Paramount E-mart`);

  // Inject share panel into the open modal
  const info = document.querySelector('#modalBody .modal-product-info');
  if (!info) return;

  // Remove any existing panel first
  const existing = document.getElementById('productSharePanel');
  if (existing) { existing.remove(); return; } // toggle off if already open

  const panel = document.createElement('div');
  panel.id = 'productSharePanel';
  panel.className = 'product-share-panel';
  panel.innerHTML = `
    <div class="psp-head">
      <span class="psp-title">Share This Product</span>
      <button class="psp-close" onclick="document.getElementById('productSharePanel').remove()">✕</button>
    </div>
    <div class="psp-serial-row">
      <span class="psp-serial-label">Serial No.</span>
      <span class="psp-serial">${serial}</span>
    </div>
    <div class="psp-link-row">
      <input class="psp-link-input" id="pspLinkInput" type="text" value="${link}" readonly onclick="this.select()"/>
      <button class="psp-copy-btn" onclick="copyShareLink('${link}')">Copy</button>
    </div>
    <div class="psp-channels">
      <a class="psp-channel psp-wa"
         href="https://wa.me/?text=${waText}"
         target="_blank" rel="noopener">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 2C6.477 2 2 6.477 2 12c0 1.89.525 3.66 1.438 5.168L2.07 21.5l4.43-1.393A9.953 9.953 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 12 2zm0 18a7.95 7.95 0 01-4.073-1.117l-.292-.174-3.03.953.947-2.96-.19-.305A7.96 7.96 0 014 12c0-4.411 3.589-8 8-8s8 3.589 8 8-3.589 8-8 8z"/></svg>
        WhatsApp
      </a>
      <a class="psp-channel psp-x"
         href="https://twitter.com/intent/tweet?text=${xText}&url=${encodeURIComponent(link)}"
         target="_blank" rel="noopener">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.747l7.73-8.835L1.254 2.25H8.08l4.259 5.63zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
        Post on X
      </a>
      <button class="psp-channel psp-copy2" onclick="copyShareLink('${link}')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
        Copy Link
      </button>
    </div>`;
  info.appendChild(panel);
}

function copyShareLink(link) {
  navigator.clipboard.writeText(link).then(() => {
    showToast('Share link copied! ✓');
    // Flash the copy button
    document.querySelectorAll('.psp-copy-btn, .psp-copy2').forEach(b => {
      b.textContent = '✓ Copied';
      setTimeout(() => {
        if (b.classList.contains('psp-copy-btn')) b.textContent = 'Copy';
        else { b.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg> Copy Link`; }
      }, 2000);
    });
  }).catch(() => {
    // Fallback for older browsers
    const inp = document.getElementById('pspLinkInput');
    if (inp) { inp.select(); document.execCommand('copy'); showToast('Link copied!'); }
  });
}


// ─── CATALOGUE SHARE ──────────────────────────
// context: 'featured' | 'shop' | 'categories' | undefined
function openCatalogueShare(context) {
  const sel = document.getElementById('catShareSelect');
  if (sel) {
    const cats = getCategories().map(c => c.name);
    sel.innerHTML = '<option value="all">All Products (Full Catalogue)</option>' +
      cats.map(c => '<option value="' + c + '">' + c + '</option>').join('');
    // Pre-select based on context
    if (context === 'shop' && typeof shopActiveFilter !== 'undefined' && shopActiveFilter !== 'All') {
      sel.value = shopActiveFilter;
    } else if (context === 'featured') {
      sel.value = 'all'; // featured = all
    }
    // Update popup title to reflect context
    const title = document.querySelector('#catalogueSharePopup .popup-title');
    if (title) {
      const labels = { featured:'Share Featured Products', shop:'Share This Catalogue', categories:'Share Category Catalogue' };
      title.textContent = labels[context] || 'Share Product Catalogue';
    }
  }
  updateCatalogueLink();
  openPopup('catalogueShareOverlay', 'catalogueSharePopup');
}
function closeCatalogueShare() { closePopup('catalogueShareOverlay', 'catalogueSharePopup'); }

function getCatalogueLink(cat) {
  const base = window.location.origin + window.location.pathname;
  if (!cat || cat === 'all') return base + '?catalogue=all';
  return base + '?catalogue=' + encodeURIComponent(cat);
}

function updateCatalogueLink() {
  const sel  = document.getElementById('catShareSelect');
  const cat  = sel ? sel.value : 'all';
  const link = getCatalogueLink(cat);
  const inp  = document.getElementById('catalogueLinkInput');
  if (inp) inp.value = link;
  const label  = cat === 'all' ? 'Full Catalogue' : cat + ' Collection';
  const waText = encodeURIComponent('Paramount E-mart - ' + label + '\n\n' + link);
  const xText  = encodeURIComponent('Browse the ' + label + ' at Paramount E-mart');
  const ch = document.getElementById('catShareChannels');
  if (!ch) return;
  const xCatText = encodeURIComponent('Browse the ' + label + ' at Paramount E-mart ' + link);
  ch.innerHTML =
    '<a class="psp-channel psp-wa" href="https://wa.me/?text=' + waText + '" target="_blank" rel="noopener">' +
    '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 2C6.477 2 2 6.477 2 12c0 1.89.525 3.66 1.438 5.168L2.07 21.5l4.43-1.393A9.953 9.953 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 12 2zm0 18a7.95 7.95 0 01-4.073-1.117l-.292-.174-3.03.953.947-2.96-.19-.305A7.96 7.96 0 014 12c0-4.411 3.589-8 8-8s8 3.589 8 8-3.589 8-8 8z"/></svg>' +
    ' WhatsApp</a>' +
    '<a class="psp-channel psp-x" href="https://twitter.com/intent/tweet?text=' + xCatText + '" target="_blank" rel="noopener">' +
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.747l7.73-8.835L1.254 2.25H8.08l4.259 5.63zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>' +
    ' Post on X</a>' +
    '<button class="psp-channel psp-copy2" onclick="copyCatalogueLink()">' +
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>' +
    ' Copy Link</button>';
}

function copyCatalogueLink() {
  const inp = document.getElementById('catalogueLinkInput');
  const link = inp ? inp.value : '';
  if (!link) return;
  navigator.clipboard.writeText(link).then(() => {
    showToast('Catalogue link copied!');
    const btn = document.getElementById('catCopyBtn');
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy'; }, 2000); }
  }).catch(() => { if (inp) { inp.select(); document.execCommand('copy'); showToast('Copied!'); } });
}

// ─── AUTO-OPEN FROM SHARE LINK ────────────────
function handleShareLinkParam() {
  const params = new URLSearchParams(window.location.search);

  // Single product share link: ?p=PES-00001
  const serial = params.get('p');
  if (serial) {
    const products = getProducts();
    const p = products.find(x => getProductSerial(x) === serial);
    if (!p) { showToast('Product not found — it may have been removed.'); return; }
    setTimeout(() => { openProductModal(p.id); }, 500);
    return;
  }

  // Catalogue share link: ?catalogue=Electronics  or  ?catalogue=all
  const cat = params.get('catalogue');
  if (cat) {
    setTimeout(() => {
      if (cat === 'all' || cat === '') {
        if (typeof openShopPopup === 'function') openShopPopup();
      } else {
        if (typeof openShopPopupFiltered === 'function') openShopPopupFiltered(decodeURIComponent(cat));
      }
    }, 500);
    return;
  }
}

function closeModal(){
  document.getElementById('productModal').classList.remove('open');
  document.getElementById('modalOverlay').classList.remove('open');
  document.body.style.overflow='';
}

// ─── CART ────────────────────────────────────
function saveCart(){ localStorage.setItem('pes_cart',JSON.stringify(cart)); }

function addToCart(productId){
  const p=getProducts().find(x=>x.id===productId);
  if(!p) return;
  const ex=cart.find(c=>c.id===productId);
  if(ex) ex.qty+=1; else cart.push({...p,qty:1});
  saveCart(); updateCartUI();
  showCartAddToast(p);
}

let _cartToastTimer = null;
function showCartAddToast(p){
  const toast = document.getElementById('cartAddToast');
  if(!toast) { showToast(`${p.name} added to cart`); return; }
  document.getElementById('catTitle').textContent = p.name;
  document.getElementById('catSub').textContent   = formatPrice(p.price);
  // Clear any running timer
  clearTimeout(_cartToastTimer);
  toast.classList.remove('cat-show');
  // Force reflow so animation restarts cleanly
  void toast.offsetWidth;
  toast.classList.add('cat-show');
  _cartToastTimer = setTimeout(()=>{ toast.classList.remove('cat-show'); }, 5000);
}

function removeFromCart(id){ cart=cart.filter(c=>c.id!==id); saveCart(); updateCartUI(); }

function changeQty(id,delta){
  const item=cart.find(c=>c.id===id);
  if(!item) return;
  item.qty+=delta;
  if(item.qty<=0) removeFromCart(id); else { saveCart(); updateCartUI(); }
}

// ─── BULK ORDER DISCOUNT HELPERS ─────────────
function getActiveBulkTier(totalQty){
  const tiers = typeof getBulkTiers==='function' ? getBulkTiers() : [];
  let active = null;
  for(const t of tiers){ if(totalQty >= t.minQty) active = t; }
  return active;
}
function applyBulkDiscount(rawTotal, totalQty){
  const tier = getActiveBulkTier(totalQty);
  if(!tier) return { discountedTotal: rawTotal, tier: null, saving: 0 };
  const saving = rawTotal * (tier.discount / 100);
  return { discountedTotal: rawTotal - saving, tier, saving };
}

// ─── CART UI ──────────────────────────────────
function updateCartUI(){
  const count    = cart.reduce((a,b)=>a+b.qty,0);
  const rawTotal = cart.reduce((a,b)=>a+b.price*b.qty,0);
  const {discountedTotal, tier, saving} = applyBulkDiscount(rawTotal, count);

  document.getElementById('cartCount').textContent = count;
  const mob = document.getElementById('mobCartCount');
  if(mob) mob.textContent = count;

  // Show/hide floating cart button based on whether items are in cart
  const floatingBtn = document.getElementById('floatingCartBtn');
  if(floatingBtn) floatingBtn.classList.toggle('floating-cart-visible', count > 0);

  const itemsEl = document.getElementById('cartItems');
  const emptyEl = document.getElementById('cartEmpty');
  const chkEl   = document.getElementById('cartCheckoutSection');

  if(cart.length === 0){
    itemsEl.innerHTML = '';
    emptyEl.style.display = 'block';
    chkEl.style.display   = 'none';
    return;
  }

  emptyEl.style.display = 'none';
  chkEl.style.display   = 'block';

  // ── Bulk discount banner ──────────────────
  const tiers    = typeof getBulkTiers==='function' ? getBulkTiers() : [];
  const nextTier = tiers.find(t => count < t.minQty);
  let bannerHtml = '';
  if(tier){
    bannerHtml = `
      <div class="bulk-discount-banner active">
        <div class="bulk-discount-label">🎉 Bulk Discount Applied — ${tier.label} (${tier.discount}% off)</div>
        <div class="bulk-discount-saving">You save ${formatPrice(saving)}</div>
      </div>`;
  } else if(nextTier){
    const needed = nextTier.minQty - count;
    bannerHtml = `
      <div class="bulk-discount-banner">
        <div class="bulk-discount-label">📦 Add ${needed} more item${needed!==1?'s':''} to unlock ${nextTier.discount}% off (${nextTier.label})</div>
        <button class="bulk-tiers-toggle" onclick="toggleBulkTiers()">View tiers ▾</button>
      </div>`;
  }

  // ── Tiers table ───────────────────────────
  const tiersHtml = `
    <div class="bulk-tiers-panel" id="bulkTiersPanel" style="display:none;">
      <div class="bulk-tiers-title">Order Discount Tiers</div>
      ${tiers.map(t=>`
        <div class="bulk-tier-row ${tier&&tier.label===t.label?'bulk-tier-active':''}">
          <span class="bulk-tier-name">${t.label}</span>
          <span class="bulk-tier-range">${t.minQty}${t.maxQty?'–'+t.maxQty:'+'} units</span>
          <span class="bulk-tier-disc">${t.discount}% off</span>
        </div>`).join('')}
      <div class="bulk-tiers-note">Auto-applied at checkout from ${tiers[0]?.minQty||5}+ units.</div>
    </div>`;

  // ── Cart items ────────────────────────────
  const itemsHtml = cart.map(item=>`
    <div class="cart-item" data-id="${item.id}">
      <div class="cart-item-img-wrap">${pImg(item.image,item.name,'cart-img')}</div>
      <div class="cart-item-info">
        <div class="cart-item-name">${item.name}</div>
        <div class="cart-item-price">${formatPrice(item.price)} each</div>
        <div class="cart-item-controls">
          <button class="qty-btn" onclick="changeQty(${item.id},-1)" aria-label="Decrease">−</button>
          <input
            class="qty-input"
            type="number"
            min="1"
            value="${item.qty}"
            aria-label="Quantity"
            onchange="setQty(${item.id}, this.value)"
            oninput="this.value=this.value.replace(/[^0-9]/g,'')"
          />
          <button class="qty-btn" onclick="changeQty(${item.id},1)" aria-label="Increase">+</button>
          <button class="cart-item-remove" onclick="removeFromCart(${item.id})" title="Remove item">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            Remove
          </button>
        </div>
      </div>
    </div>`).join('');

  itemsEl.innerHTML = bannerHtml + tiersHtml + itemsHtml;

  // ── Total display ─────────────────────────
  const totalEl = document.getElementById('cartTotal');
  if(tier){
    totalEl.innerHTML = `<span class="cart-total-original">${formatPrice(rawTotal)}</span>${formatPrice(discountedTotal)}`;
  } else {
    totalEl.textContent = formatPrice(rawTotal);
  }
}

// Set exact qty from typed input
function setQty(id, rawVal){
  const val = parseInt(rawVal);
  if(isNaN(val) || val < 1){
    // revert to current qty visually
    updateCartUI();
    return;
  }
  const item = cart.find(c=>c.id===id);
  if(!item) return;
  item.qty = val;
  saveCart();
  updateCartUI();
}

// Clear entire cart
function clearCart(){
  if(!cart.length) return;
  pesDanger(
    'This will remove all items from your cart.',
    'Clear Cart',
    function() { cart = []; saveCart(); updateCartUI(); showToast('Cart cleared'); },
    null,
    { title: 'Clear Cart?', icon: '🛒' }
  );
}

function toggleBulkTiers(){
  const panel = document.getElementById('bulkTiersPanel');
  if(!panel) return;
  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';
  const btn = document.querySelector('.bulk-tiers-toggle');
  if(btn) btn.textContent = isOpen ? 'View tiers ▾' : 'Hide tiers ▴';
}

function toggleCart(){
  document.getElementById('cartDrawer').classList.toggle('open');
  document.getElementById('cartOverlay').classList.toggle('open');
  document.body.style.overflow=document.getElementById('cartDrawer').classList.contains('open')?'hidden':'';
}

// ─── CHECKOUT ────────────────────────────────
function initiateCheckout(){
  _activePromo = null; // reset promo on new checkout
  _deliveryFee = 500;
  toggleCart();
  setTimeout(()=>{
    const count=cart.reduce((a,b)=>a+b.qty,0);
    const rawTotal=cart.reduce((a,b)=>a+b.price*b.qty,0);
    const {discountedTotal, tier, saving}=applyBulkDiscount(rawTotal, count);
    document.getElementById('checkoutSummary').innerHTML=cart.map(item=>`
      <div class="checkout-summary-item">
        <div class="checkout-summary-img-wrap">${pImg(item.image,item.name,'checkout-img')}</div>
        <div class="checkout-summary-info">
          <div class="checkout-summary-name">${item.name}</div>
          <div class="checkout-summary-qty">Qty: ${item.qty}</div>
        </div>
        <div class="checkout-summary-price">${formatPrice(item.price*item.qty)}</div>
      </div>
    `).join('')+(tier?`
      <div style="margin-top:12px;padding:12px 14px;background:#0f1a0f;border:1px solid #2d4a2d;display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:11px;color:#6fcf97;font-weight:600;">📦 ${tier.label} Bulk Discount (−${tier.discount}%)</span>
        <span style="font-size:12px;color:#6fcf97;">−${formatPrice(saving)}</span>
      </div>`:'');
    const summaryEl=document.getElementById('summaryTotal');
    if(tier){
      summaryEl.innerHTML=`<span style="text-decoration:line-through;color:#555;font-size:13px;margin-right:6px;">${formatPrice(rawTotal)}</span>${formatPrice(discountedTotal)}`;
    } else {
      summaryEl.textContent=formatPrice(rawTotal);
    }
    document.getElementById('checkoutModal').classList.add('open');
    document.getElementById('checkoutOverlay').classList.add('open');
    document.body.style.overflow='hidden';
    _populateCountrySelect();
  },300);
}

function closeCheckout(){
  document.getElementById('checkoutModal').classList.remove('open');
  document.getElementById('checkoutOverlay').classList.remove('open');
  document.body.style.overflow='';
}

// ─── PAYMENT GATEWAY ROUTER ──────────────────
// Active gateway is set by selectPaymentMethod() or defaults to 'flutterwave'
let _activeGateway = localStorage.getItem('pes_active_gateway') || 'flutterwave';

function selectPaymentMethod(gateway, btnEl) {
  _activeGateway = gateway;
  // Update button states
  document.querySelectorAll('.payment-method-btn').forEach(b => b.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');
  // Update note and button label
  const notes = {
    flutterwave: '🔒 Secured by <strong>Flutterwave</strong>. Cards, mobile money & bank transfers.',
    opay:        '🔒 Pay via <strong>OPay</strong>. Instant wallet transfer, bank & USSD. Nigeria only.',
    crypto:      '🔒 Pay with <strong>Crypto</strong>. USDT (TRC20/ERC20), BTC or ETH. Wallet address shown after clicking pay.',
  };
  const labels = {
    flutterwave: 'Pay with Flutterwave',
    opay:        'Pay with OPay',
    crypto:      'Pay with Crypto',
  };
  const noteEl = document.getElementById('paymentNote');
  const btnTxt = document.getElementById('payBtnText');
  if (noteEl) noteEl.innerHTML = typeof notes[gateway] === 'function' ? notes[gateway]() : (notes[gateway] || notes.flutterwave);
  if (btnTxt) btnTxt.textContent = labels[gateway] || 'Pay Now';
}

// ── Shared order-completion handler (all gateways call this) ──
function _onPaymentSuccess(reference, name, email, phone, address, total, rawTotal, tier) {
  const orderId  = 'PES-' + Date.now();
  const actualDelivery = (_activePromo && _activePromo.type === 'shipping') ? 0 : (_deliveryFee || 0);
  const orderData = {
    id: orderId, customer: name, email, phone, address,
    items: [...cart], total, rawTotal,
    bulkTier: tier?.label || null,
    promoCode: _activePromo ? _activePromo.code : null,
    deliveryFee: actualDelivery,
    reference,
    gateway: _activeGateway,
    status: 'paid',
    date: new Date().toLocaleDateString('en-NG',{day:'numeric',month:'short',year:'numeric'})
  };
  addOrder(orderData);
  const shipment = createShipmentFromOrder(orderData);
  if (typeof addShipment === 'function') addShipment(shipment);
  if (typeof saveCustomerToSheets === 'function')
    saveCustomerToSheets({name, email, phone, address, source:'Store Checkout'});
  if (typeof saveOrderToSheets === 'function')
    saveOrderToSheets({
      orderId, trackingId: shipment.id,
      customer: name, email, phone, address,
      items: cart.map(i => i.name + ' x' + i.qty).join(', '),
      total, reference, gateway: _activeGateway,
      date: new Date().toISOString()
    });
  sendDeliveryConfirmationEmail({
    orderId, trackingId: shipment.id,
    customerName: name, customerEmail: email,
    phone, address,
    items: cart.map(i => i.name + ' ×' + i.qty).join(', '),
    total: formatPrice(total),
    estimatedDelivery: shipment.estimatedDelivery,
    destination: shipment.destination.city,
    reference
  });
  cart = []; saveCart(); updateCartUI(); closeCheckout(); _activePromo = null; _deliveryFee = 500;
  localStorage.removeItem('pes_abandoned_cart');
  showSuccessScreen(name, reference, total, shipment.id);
  _notifyOwnerWhatsApp(orderData, shipment.id);
}

function processPayment() {
  const name    = document.getElementById('chkName').value.trim();
  const email   = document.getElementById('chkEmail').value.trim();
  const phone   = document.getElementById('chkPhone').value.trim();
  const address = document.getElementById('chkAddress')?.value.trim() || '';
  if (!cart.length) { showToast('Your cart is empty'); return; }
  if (!name || !email || !phone) { showToast('Please fill in all your details'); return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showToast('Please enter a valid email address'); return; }
  const count = cart.reduce((a,b)=>a+b.qty, 0);
  const rawTotal = cart.reduce((a,b)=>a+b.price*b.qty, 0);
  const { discountedTotal, tier } = applyBulkDiscount(rawTotal, count);
  const promoDisc = typeof getPromoDiscount === 'function' ? getPromoDiscount(discountedTotal) : 0;
  const actualDelivery = (_activePromo && _activePromo.type === 'shipping') ? 0 : (_deliveryFee || 0);
  const total = discountedTotal - promoDisc + actualDelivery;

  const gateway = _activeGateway || 'flutterwave';
  if      (gateway === 'flutterwave') _payWithFlutterwave(name, email, phone, address, total, rawTotal, tier);
  else if (gateway === 'opay')        _payWithOpay(name, email, phone, address, total, rawTotal, tier);
  else if (gateway === 'crypto')      _payWithCrypto(name, email, phone, address, total, rawTotal, tier);
  else                                _payWithFlutterwave(name, email, phone, address, total, rawTotal, tier);
}

// ── FLUTTERWAVE ───────────────────────────────
function _payWithFlutterwave(name, email, phone, address, total, rawTotal, tier) {
  const btn = document.getElementById('payBtnText');
  if (btn) btn.textContent = 'Opening Flutterwave…';
  const key      = localStorage.getItem('pes_flutterwave_key') || 'FLWPUBK_TEST-YOUR_FLUTTERWAVE_KEY';
  const currency = localStorage.getItem('pes_flutterwave_currency') || 'NGN';
  // If currency is not NGN, convert using live rate
  const flwAmount = currency === 'NGN'
    ? total
    : parseFloat((total / (typeof getLiveRate === 'function' ? getLiveRate(currency) : 1600)).toFixed(2));
  if (typeof FlutterwaveCheckout === 'undefined') {
    pesAlert('Flutterwave SDK not loaded. Please check your internet connection and try again.',
      null, { title: 'Gateway Error', icon: '⚠️' });
    if (btn) btn.textContent = 'Pay with Flutterwave';
    return;
  }
  FlutterwaveCheckout({
    public_key: key,
    tx_ref:     'PES-FLW-' + Date.now(),
    amount:     flwAmount,
    currency:   currency,
    payment_options: 'card, banktransfer, ussd, account',
    customer: { email, phone_number: phone, name },
    meta: {
      address,
      products: cart.map(c=>c.name+' x'+c.qty).join(', '),
      bulk_tier: tier ? tier.label : 'none'
    },
    customizations: {
      title:       'Paramount E-mart',
      description: cart.map(c=>c.name+' x'+c.qty).join(', ').substring(0, 100),
      logo:        window.location.origin + '/images/logo.png'
    },
    callback(res) {
      if (res.status === 'successful' || res.status === 'completed') {
        _onPaymentSuccess(res.transaction_id || res.tx_ref, name, email, phone, address, total, rawTotal, tier);
      } else {
        if (btn) btn.textContent = 'Pay with Flutterwave';
        showToast('Payment not completed. Please try again.');
      }
    },
    onclose() { if (btn) btn.textContent = 'Pay with Flutterwave'; }
  });
}




// ── OPAY ──────────────────────────────────────
function _payWithOpay(name, email, phone, address, total, rawTotal, tier) {
  var orderId    = 'PES-' + Date.now();
  var opayNumber = localStorage.getItem('pes_opay_number') || '09131514244';
  var waLink     = 'https://wa.me/2349160439848?text=' + encodeURIComponent(
    'Hi! I just paid \u20a6' + Number(total).toLocaleString() +
    ' via OPay for my order.\nRef: ' + orderId + '\nCustomer: ' + name +
    '\n\nPlease confirm my order. Thank you!'
  );

  var overlay = document.createElement('div');
  overlay.id = 'opayOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.88);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;';
  overlay.innerHTML =
    '<div style="background:#1a1a2e;border-radius:16px;padding:32px;max-width:420px;width:100%;text-align:center;font-family:Montserrat,sans-serif;">' +
      '<div style="font-size:48px;margin-bottom:12px;">\uD83D\uDCF1</div>' +
      '<h2 style="color:#00BF63;font-size:20px;margin:0 0 8px;">Pay via OPay</h2>' +
      '<p style="color:#aaa;font-size:13px;margin:0 0 24px;line-height:1.6;">' +
        'Transfer <strong style="color:#fff;">\u20a6' + Number(total).toLocaleString() + '</strong> ' +
        'to the OPay wallet below, then confirm on WhatsApp.' +
      '</p>' +
      '<div style="background:#0f3460;border-radius:10px;padding:20px;margin-bottom:20px;text-align:left;">' +
        '<div style="color:#aaa;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:6px;">OPay Number</div>' +
        '<div style="color:#00BF63;font-size:26px;font-weight:700;letter-spacing:0.06em;margin-bottom:12px;">' + opayNumber + '</div>' +
        '<div style="color:#aaa;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:6px;">Account Name</div>' +
        '<div style="color:#fff;font-size:15px;font-weight:600;margin-bottom:12px;">Paramount E-mart</div>' +
        '<div style="color:#aaa;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:6px;">Order Reference</div>' +
        '<div style="color:#fff;font-size:14px;font-weight:600;font-family:monospace;">' + orderId + '</div>' +
      '</div>' +
      '<p style="color:#aaa;font-size:12px;margin:0 0 20px;line-height:1.6;">' +
        'After paying, tap <strong style="color:#fff;">Confirm on WhatsApp</strong> and send your screenshot. ' +
        'Your order will be processed within 30 minutes.' +
      '</p>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">' +
        '<a href="' + waLink + '" target="_blank" ' +
          'style="display:flex;align-items:center;justify-content:center;gap:8px;background:#25D366;color:#fff;' +
          'border-radius:8px;padding:13px;font-size:13px;font-weight:700;text-decoration:none;">' +
          '\uD83D\uDCF2 Confirm on WhatsApp' +
        '</a>' +
        '<button onclick="document.getElementById(\'opayOverlay\').remove()" ' +
          'style="background:#1e1e3a;color:#aaa;border:1px solid #333;border-radius:8px;padding:13px;' +
          'font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;">Cancel</button>' +
      '</div>' +
    '</div>';

  document.body.appendChild(overlay);
  overlay.addEventListener('click', function(e){ if (e.target === overlay) overlay.remove(); });
}


// ── CRYPTO PAYMENT ────────────────────────────
function _payWithCrypto(name, email, phone, address, total, rawTotal, tier) {
  var orderId   = 'PES-' + Date.now();
  var usdtTrc20 = localStorage.getItem('pes_crypto_usdt_trc20') || '';
  var usdtErc20 = localStorage.getItem('pes_crypto_usdt_erc20') || '';
  var btcAddr   = localStorage.getItem('pes_crypto_btc')        || '';
  var ethAddr   = localStorage.getItem('pes_crypto_eth')        || '';
  var usdRate   = typeof getLiveRate === 'function' ? getLiveRate('USD') : 1600;
  var totalUSD  = (total / usdRate).toFixed(2);
  var totalNGN  = Number(total).toLocaleString();

  var prev = document.getElementById('cryptoOverlay');
  if (prev) prev.remove();

  function addrRow(coin, addr, color, net) {
    if (!addr) return '';
    var safe = addr.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    return '<div style="background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:10px;">' +
      '<div style="display:flex;justify-content:space-between;margin-bottom:8px;">' +
        '<span style="color:' + color + ';font-weight:700;font-size:13px;">' + coin + '</span>' +
        '<span style="color:#888;font-size:11px;">' + net + '</span>' +
      '</div>' +
      '<div onclick="(function(){navigator.clipboard&&navigator.clipboard.writeText(\'' + safe + '\').then(function(){showToast(\'' + coin + ' address copied!\');});})()" ' +
        'style="background:#161b22;border-radius:6px;padding:10px 14px;cursor:pointer;' +
        'word-break:break-all;font-family:monospace;font-size:11px;color:#e6edf3;">' +
        addr + ' <span style="color:#888;font-size:10px;">\u2398 tap to copy</span>' +
      '</div>' +
    '</div>';
  }

  var hasWallet = usdtTrc20 || usdtErc20 || btcAddr || ethAddr;
  var walletsHtml = hasWallet
    ? addrRow('USDT', usdtTrc20, '#26A17B', 'TRC20 \u00b7 Tron') +
      addrRow('USDT', usdtErc20, '#627EEA', 'ERC20 \u00b7 Ethereum') +
      addrRow('BTC',  btcAddr,   '#F7931A', 'Bitcoin') +
      addrRow('ETH',  ethAddr,   '#627EEA', 'Ethereum')
    : '<div style="background:#1a1a00;border:1px solid #444;border-radius:8px;padding:16px;color:#aaa;font-size:13px;margin-bottom:12px;">' +
        '\u26a0\ufe0f Wallet addresses not set yet. Please contact us on WhatsApp to arrange.' +
      '</div>';

  var coinOptions =
    (usdtTrc20 ? '<option value="USDT-TRC20">USDT (TRC20 \u00b7 Tron)</option>' : '') +
    (usdtErc20 ? '<option value="USDT-ERC20">USDT (ERC20 \u00b7 Ethereum)</option>' : '') +
    (btcAddr   ? '<option value="BTC">Bitcoin (BTC)</option>' : '') +
    (ethAddr   ? '<option value="ETH">Ethereum (ETH)</option>' : '') +
    '<option value="OTHER">Other</option>';

  var overlay = document.createElement('div');
  overlay.id = 'cryptoOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.93);' +
    'z-index:99999;display:flex;align-items:flex-start;justify-content:center;padding:20px;overflow-y:auto;overscroll-behavior:contain;';

  var inputStyle = 'width:100%;background:#161b22;border:1px solid #30363d;border-radius:6px;' +
    'padding:12px;color:#e6edf3;font-family:inherit;font-size:13px;box-sizing:border-box;';
  var btnPrimary = 'background:#238636;color:#fff;border:none;border-radius:8px;padding:14px;' +
    'font-size:13px;font-weight:700;cursor:pointer;font-family:inherit;width:100%;margin-bottom:8px;';
  var btnGhost = 'background:none;border:1px solid #30363d;color:#888;border-radius:8px;padding:12px;' +
    'font-size:13px;cursor:pointer;font-family:inherit;width:100%;';

  overlay.innerHTML =
    '<div style="background:#0d1117;border:1px solid #30363d;border-radius:16px;padding:28px;' +
    'max-width:460px;width:100%;font-family:Montserrat,sans-serif;margin:auto;">' +

    // ── Step 1 ──────────────────────────────────
    '<div id="cpoStep1">' +
      '<div style="text-align:center;margin-bottom:20px;">' +
        '<div style="font-size:44px;margin-bottom:8px;">\u20bf</div>' +
        '<h2 style="color:#e6edf3;font-size:20px;margin:0 0 6px;">Pay with Crypto</h2>' +
        '<p style="color:#888;font-size:13px;margin:0;">Send the exact amount to one wallet below.</p>' +
      '</div>' +
      '<div style="background:#161b22;border-radius:8px;padding:14px;margin-bottom:14px;display:flex;gap:10px;">' +
        '<div style="flex:1;text-align:center;">' +
          '<div style="color:#888;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:3px;">USDT Amount</div>' +
          '<div style="color:#26A17B;font-size:20px;font-weight:700;">$' + totalUSD + '</div>' +
        '</div>' +
        '<div style="width:1px;background:#30363d;"></div>' +
        '<div style="flex:1;text-align:center;">' +
          '<div style="color:#888;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:3px;">NGN Amount</div>' +
          '<div style="color:#e6edf3;font-size:20px;font-weight:700;">\u20a6' + totalNGN + '</div>' +
        '</div>' +
      '</div>' +
      walletsHtml +
      '<div style="background:#1a0a0a;border:1px solid #5a1a1a;border-radius:8px;padding:12px;margin-bottom:16px;font-size:12px;color:#f85149;">' +
        '\u26a0\ufe0f Send the <strong>exact</strong> amount shown. Wrong amounts or wrong networks cannot be reversed.' +
      '</div>' +
      '<button onclick="document.getElementById(\'cpoStep1\').style.display=\'none\';document.getElementById(\'cpoStep2\').style.display=\'block\';" ' +
        'style="' + btnPrimary + '">\u2713 I\'ve Sent the Payment \u2014 Verify Now</button>' +
      '<button onclick="document.getElementById(\'cryptoOverlay\').remove()" style="' + btnGhost + '">Cancel</button>' +
    '</div>' +

    // ── Step 2 ──────────────────────────────────
    '<div id="cpoStep2" style="display:none;">' +
      '<div style="text-align:center;margin-bottom:20px;">' +
        '<div style="font-size:44px;margin-bottom:8px;color:#238636;">\u2713</div>' +
        '<h2 style="color:#e6edf3;font-size:20px;margin:0 0 6px;">Verify Your Payment</h2>' +
        '<p style="color:#888;font-size:13px;margin:0;">Paste your transaction hash (TXID) below.</p>' +
      '</div>' +
      '<div style="margin-bottom:12px;">' +
        '<label style="color:#888;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;display:block;margin-bottom:6px;">Transaction Hash / TXID</label>' +
        '<input id="cpoTxHash" type="text" placeholder="e.g. 0x4a3b2c1d\u2026" autocomplete="off" style="' + inputStyle + '"/>' +
      '</div>' +
      '<div style="margin-bottom:12px;">' +
        '<label style="color:#888;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;display:block;margin-bottom:6px;">Coin Sent</label>' +
        '<select id="cpoCoin" style="' + inputStyle + '">' + coinOptions + '</select>' +
      '</div>' +
      '<div style="margin-bottom:12px;">' +
        '<label style="color:#888;font-size:10px;letter-spacing:0.12em;text-transform:uppercase;display:block;margin-bottom:6px;">Amount Sent</label>' +
        '<input id="cpoCoinAmount" type="text" placeholder="e.g. 12.50" style="' + inputStyle + '"/>' +
      '</div>' +
      '<div id="cpoVerifyMsg" style="display:none;padding:12px;border-radius:6px;font-size:12px;margin-bottom:12px;"></div>' +
      '<button id="cpoVerifyBtn" ' +
        'onclick="_cryptoSubmit(\'' + encodeURIComponent(orderId) + '\',\'' + totalUSD + '\',\'' + totalNGN + '\',' + total + ',' + rawTotal + ',\'' + encodeURIComponent(name) + '\',\'' + encodeURIComponent(email) + '\',\'' + encodeURIComponent(phone) + '\',\'' + encodeURIComponent(address) + '\')" ' +
        'style="' + btnPrimary + '">Submit for Verification</button>' +
      '<button onclick="document.getElementById(\'cpoStep2\').style.display=\'none\';document.getElementById(\'cpoStep1\').style.display=\'block\';" ' +
        'style="' + btnGhost + '">\u2190 Back</button>' +
      '<p style="text-align:center;margin-top:16px;font-size:12px;color:#888;">' +
        'Prefer WhatsApp? ' +
        '<a href="https://wa.me/2349160439848?text=' + encodeURIComponent('Hi! Crypto payment for Ref: ' + orderId + ' — ' + name + '. Sending screenshot + hash.') + '" ' +
        'target="_blank" style="color:#26A17B;font-weight:600;">Send proof here \u2192</a>' +
      '</p>' +
    '</div>' +

    // ── Step 3 ──────────────────────────────────
    '<div id="cpoStep3" style="display:none;text-align:center;">' +
      '<div style="font-size:64px;margin-bottom:16px;color:#238636;">\u2713</div>' +
      '<h2 style="color:#e6edf3;font-size:20px;margin:0 0 10px;">Submitted!</h2>' +
      '<p style="color:#888;font-size:13px;line-height:1.7;margin-bottom:16px;">' +
        'Your transaction has been recorded. We will verify within ' +
        '<strong style="color:#e6edf3;">15\u201330 minutes</strong> ' +
        'and confirm via email & WhatsApp.' +
      '</p>' +
      '<div style="background:#0d2818;border:1px solid #1a4a2a;border-radius:8px;padding:12px;margin-bottom:20px;font-size:13px;">' +
        'Order Ref: <strong id="cpoSuccessRef" style="color:#26A17B;font-family:monospace;">' + orderId + '</strong>' +
      '</div>' +
      '<button id="cpoConfirmOrderBtn" style="' + btnPrimary + '">Close & Continue Shopping</button>' +
    '</div>' +

    '</div>';

  document.body.appendChild(overlay);
  overlay.addEventListener('click', function(e){ if (e.target === overlay) overlay.remove(); });
  overlay._data = { orderId:orderId, name:name, email:email, phone:phone, address:address, total:total, rawTotal:rawTotal, tier:tier, totalUSD:totalUSD, totalNGN:totalNGN };
}

async function _cryptoSubmit(encOrderId, totalUSD, totalNGN, total, rawTotal, encName, encEmail, encPhone, encAddress) {
  var orderId = decodeURIComponent(encOrderId);
  var name    = decodeURIComponent(encName);
  var email   = decodeURIComponent(encEmail);
  var phone   = decodeURIComponent(encPhone);
  var address = decodeURIComponent(encAddress);

  var txEl    = document.getElementById('cpoTxHash');
  var coinEl  = document.getElementById('cpoCoin');
  var amtEl   = document.getElementById('cpoCoinAmount');
  var msgEl   = document.getElementById('cpoVerifyMsg');
  var btn     = document.getElementById('cpoVerifyBtn');

  var txHash  = txEl  ? txEl.value.trim()  : '';
  var coin    = coinEl ? coinEl.value       : 'USDT-TRC20';
  var coinAmt = amtEl  ? amtEl.value.trim() : '';

  function showMsg(text, ok) {
    if (!msgEl) return;
    msgEl.style.display  = 'block';
    msgEl.style.background = ok ? '#0d2818' : '#3a0f0f';
    msgEl.style.color      = ok ? '#56d364' : '#f85149';
    msgEl.style.border     = '1px solid ' + (ok ? '#1a4a2a' : '#5a1a1a');
    msgEl.textContent = text;
  }

  if (!txHash || txHash.length < 8) { showMsg('\u26a0\ufe0f Please enter your transaction hash / TXID.', false); return; }

  if (btn) { btn.textContent = 'Submitting\u2026'; btn.disabled = true; }

  // Record order as pending-crypto
  var ov   = document.getElementById('cryptoOverlay');
  var tier = ov && ov._data ? ov._data.tier : null;
  try {
    _onPaymentSuccess('CRYPTO-PENDING-' + txHash.substring(0, 12), name, email, phone, address, total, rawTotal, tier);
  } catch(e) {}

  // Notify server (non-blocking)
  var SERVER = location.protocol === 'file:' ? 'http://localhost:3000' : location.origin;
  try {
    await fetch(SERVER + '/api/crypto-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orderId:orderId, txHash:txHash, coin:coin, coinAmount:coinAmt, totalUSD:totalUSD, totalNGN:totalNGN, name:name, email:email })
    }).catch(function(){});
  } catch(e) {}

  // Open WhatsApp with proof request
  var waMsg = encodeURIComponent(
    '\uD83D\uDD10 *Crypto Payment Verification*\n' +
    '\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
    '*Order:* ' + orderId + '\n' +
    '*Customer:* ' + name + '\n' +
    '*Coin:* ' + coin + '\n' +
    '*Amount:* ' + (coinAmt || '?') + ' \u2248 $' + totalUSD + ' (\u20a6' + totalNGN + ')\n' +
    '*TX Hash:* ' + txHash + '\n' +
    '\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
    'Please verify and confirm this order.'
  );
  window.open('https://wa.me/2349160439848?text=' + waMsg, '_blank', 'noopener');

  // Show step 3
  var s2 = document.getElementById('cpoStep2');
  var s3 = document.getElementById('cpoStep3');
  if (s2) s2.style.display = 'none';
  if (s3) s3.style.display = 'block';

  var confirmBtn = document.getElementById('cpoConfirmOrderBtn');
  if (confirmBtn) {
    confirmBtn.onclick = function() {
      var overlay = document.getElementById('cryptoOverlay');
      if (overlay) overlay.remove();
      closeCheckout();
    };
  }
}


// ── OWNER WHATSAPP NOTIFICATION ────────────────
// Fires silently after every successful payment
function _notifyOwnerWhatsApp(order, trackingId) {
  try {
    var ownerPhone = (localStorage.getItem('pes_business_phone') || '+2349160439848').replace(/[^0-9]/g, '');
    if (!ownerPhone) return;
    var items = (order.items || []).map(function(i){ return '\u2022 ' + i.name + ' \u00d7' + i.qty; }).join('\n');
    var msg = encodeURIComponent(
      '\uD83D\uDED2 *NEW ORDER \u2014 Paramount E-mart*\n' +
      '\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
      '*Order ID:* ' + order.id + '\n' +
      '*Customer:* ' + order.customer + '\n' +
      '*Phone:* ' + order.phone + '\n' +
      '*Email:* ' + order.email + '\n' +
      '*Address:* ' + order.address + '\n\n' +
      '*Items:*\n' + items + '\n\n' +
      '*Total:* \u20a6' + Number(order.total).toLocaleString() + '\n' +
      '*Gateway:* ' + (order.gateway || 'Flutterwave') + '\n' +
      '*Ref:* ' + order.reference + '\n' +
      (trackingId ? '*Tracking:* ' + trackingId + '\n' : '') +
      '\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
      '\uD83D\uDCE6 Please process and dispatch this order.'
    );
    var a = document.createElement('a');
    a.href = 'https://wa.me/' + ownerPhone + '?text=' + msg;
    a.target = '_blank'; a.rel = 'noopener noreferrer'; a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){ a.remove(); }, 1000);
  } catch(e) {}
}


function showSuccessScreen(name, ref, total, trackingId){
  const el = document.createElement('div');
  el.style.cssText = 'position:fixed;inset:0;background:rgba(8,8,8,0.98);display:flex;align-items:center;justify-content:center;z-index:9999;flex-direction:column;text-align:center;padding:40px 24px;animation:fadeUp 0.5s ease;overflow-y:auto;';
  el.innerHTML = `
    <div style="width:72px;height:72px;border:2px solid #fff;display:flex;align-items:center;justify-content:center;font-size:28px;margin-bottom:32px;flex-shrink:0;">✓</div>
    <h2 style="font-family:'Cormorant Garamond',serif;font-size:clamp(32px,6vw,48px);font-weight:300;margin-bottom:16px;">Payment Confirmed</h2>
    <p style="color:#888;font-size:13px;letter-spacing:0.1em;margin-bottom:8px;">Thank you, ${name}. Your order is being processed.</p>
    <p style="color:#555;font-size:11px;letter-spacing:0.2em;margin-bottom:24px;">REF: ${ref}</p>
    <p style="color:#888;font-size:14px;margin-bottom:32px;">Total paid: <strong style="color:#f5f5f0;font-family:'Cormorant Garamond',serif;font-size:22px;">${formatPrice(total)}</strong></p>
    ${trackingId ? `
    <div style="background:#0a140a;border:1px solid #2d4a2d;padding:20px 28px;margin-bottom:32px;max-width:460px;width:100%;">
      <div style="font-size:9px;color:#4caf50;letter-spacing:0.35em;text-transform:uppercase;margin-bottom:10px;">Your Tracking ID</div>
      <div style="font-size:22px;font-weight:700;color:#fff;letter-spacing:0.15em;font-family:'Montserrat',sans-serif;margin-bottom:10px;">${trackingId}</div>
      <div style="font-size:11px;color:#666;margin-bottom:14px;">A confirmation email with your tracking details has been sent to you.</div>
      <a href="tracking.html?id=${trackingId}" style="display:inline-block;background:#4caf50;color:#000;border:none;padding:12px 28px;font-family:'Montserrat',sans-serif;font-size:10px;font-weight:700;letter-spacing:0.2em;text-transform:uppercase;cursor:pointer;text-decoration:none;">Track My Order →</a>
    </div>` : ''}
    <button onclick="this.parentElement.remove()" style="background:#fff;color:#000;border:none;padding:16px 40px;font-family:'Montserrat',sans-serif;font-size:11px;font-weight:700;letter-spacing:0.25em;text-transform:uppercase;cursor:pointer;">Continue Shopping</button>
  `;
  document.body.appendChild(el);
}

// ── DELIVERY CONFIRMATION EMAIL ───────────────────────
// Uses Google Apps Script (configured in Admin → Integrations) OR EmailJS
async function sendDeliveryConfirmationEmail(data) {
  // Option 1: Google Apps Script (preferred — no extra setup needed if GSheet is configured)
  const gasUrl = localStorage.getItem('pes_gsheet_url');
  if (gasUrl) {
    try {
      await fetch(gasUrl, {
        method: 'POST',
        mode: 'no-cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sheet: 'DeliveryEmails',
          action: 'sendEmail',
          to: data.customerEmail,
          bcc: localStorage.getItem('pes_business_email') || '',
          subject: `Your Paramount E-mart Order — Tracking ID: ${data.trackingId}`,
          body: buildDeliveryEmailBody(data),
          data
        })
      });
    } catch(e) { console.warn('GAS email send failed:', e); }
  }

  // Option 2: EmailJS (if configured in Admin → Integrations)
  const ejsServiceId  = localStorage.getItem('pes_emailjs_service');
  const ejsTemplateId = localStorage.getItem('pes_emailjs_template');
  const ejsPublicKey  = localStorage.getItem('pes_emailjs_key');
  if (ejsServiceId && ejsTemplateId && ejsPublicKey && typeof emailjs !== 'undefined') {
    try {
      await emailjs.send(ejsServiceId, ejsTemplateId, {
        to_email:      data.customerEmail,
        to_name:       data.customerName,
        order_id:      data.orderId,
        tracking_id:   data.trackingId,
        items:         data.items,
        total:         data.total,
        address:       data.address,
        est_delivery:  data.estimatedDelivery,
        destination:   data.destination,
        reference:     data.reference,
        tracking_url:  window.location.origin + '/tracking.html?id=' + data.trackingId
      }, ejsPublicKey);
    } catch(e) { console.warn('EmailJS send failed:', e); }
  }
}

function buildDeliveryEmailBody(d) {
  return [
    'Dear ' + d.customerName + ',',
    '',
    'Thank you for your purchase at Paramount E-mart. Your payment has been confirmed.',
    '',
    '--- ORDER DETAILS ---',
    'Order ID:        ' + d.orderId,
    'Reference:       ' + d.reference,
    'Items:           ' + d.items,
    'Total Paid:      ' + d.total,
    '',
    '--- DELIVERY DETAILS ---',
    'Tracking ID:     ' + d.trackingId,
    'Delivery To:     ' + d.address,
    'Destination:     ' + d.destination,
    'Est. Delivery:   ' + d.estimatedDelivery,
    '',
    'Track your order at:',
    window.location.origin + '/tracking.html?id=' + d.trackingId,
    '',
    '--- CONTACT ---',
    'Phone: +234 916 043 9848',
    'Email: paramountdigitalservices@gmail.com',
    '',
    'Thank you for shopping with Paramount E-mart.',
    'The Paramount Team'
  ].join('\n');
}

document.addEventListener('keydown',e=>{ if(e.key==='Escape'){
  closeModal(); closeCheckout();
  closeSearchPopup(); closeFeaturedPopup(); closeShopPopup(); closeCategoriesPopup(); closeContactPopup();
  closeNavSearch();
  if(typeof closePrivacyPolicy==='function')  closePrivacyPolicy();
  if(typeof closeTermsConditions==='function') closeTermsConditions();
  if(typeof closeRefundPolicy==='function')    closeRefundPolicy();
  // close hero search if open (legacy)
  const hs = document.getElementById('heroSearchSection');
  if(hs && hs.classList.contains('open')) toggleHeroSearch();
}});

// ─── NAV SEARCH DROPDOWN ─────────────────────
let navDropActiveCat = 'All';
let _navDropOpen = false;

function toggleNavSearch(){
  if(_navDropOpen) closeNavSearch(); else openNavSearch();
}

function openNavSearch(){
  const drop = document.getElementById('navSearchDropdown');
  const overlay = document.getElementById('navSearchOverlay');
  const btn = document.getElementById('navSearchBtn');
  if(!drop) return;
  // Set top offset from actual nav height
  const nav = document.querySelector('.nav');
  if(nav) drop.style.top = nav.getBoundingClientRect().height + 'px';
  drop.classList.add('open');
  overlay.classList.add('open');
  btn?.classList.add('active');
  document.body.style.overflow = 'hidden';
  _navDropOpen = true;
  buildNavDropFilters();
  setTimeout(()=>{
    const inp = document.getElementById('navDropSearchInput');
    if(inp) inp.focus();
  }, 120);
}

function closeNavSearch(){
  document.getElementById('navSearchDropdown')?.classList.remove('open');
  document.getElementById('navSearchOverlay')?.classList.remove('open');
  document.getElementById('navSearchBtn')?.classList.remove('active');
  document.body.style.overflow = '';
  _navDropOpen = false;
}

function buildNavDropFilters(){
  const wrap = document.getElementById('navDropCatFilters');
  if(!wrap) return;
  const cats = ['All', ...getCategories().map(c=>c.name)];
  wrap.innerHTML = cats.map(c=>`
    <button class="hero-filter-chip ${c===navDropActiveCat?'active':''}"
      onclick="setNavDropCat('${c.replace(/'/g,"\\'")}')">
      ${c}
    </button>`).join('');
}

function setNavDropCat(cat){
  navDropActiveCat = cat;
  buildNavDropFilters();
  runNavDropSearch();
}

function runNavDropSearch(){
  const inp = document.getElementById('navDropSearchInput');
  const q = (inp?.value||'').trim().toLowerCase();
  const clr = document.getElementById('navDropClear');
  if(clr) clr.style.display = q ? 'flex' : 'none';

  const resultsEl = document.getElementById('navDropResults');
  if(!resultsEl) return;

  if(!q && navDropActiveCat === 'All'){
    resultsEl.innerHTML = `<div class="nav-search-drop-hint">Start typing to search, or pick a category above.</div>`;
    return;
  }

  let prods = getProducts();
  if(q) prods = prods.filter(p=>
    p.name.toLowerCase().includes(q) ||
    p.category.toLowerCase().includes(q) ||
    (p.description||'').toLowerCase().includes(q)
  );
  if(navDropActiveCat !== 'All') prods = prods.filter(p=>p.category===navDropActiveCat);

  if(!prods.length){
    resultsEl.innerHTML = `<div class="nav-drop-no-results">No products found for "<strong>${q||navDropActiveCat}</strong>". Try a different search.</div>`;
    return;
  }

  resultsEl.innerHTML = prods.slice(0,12).map(p=>`
    <div class="nav-drop-item" onclick="closeNavSearch(); openProductModal(${p.id})">
      <div class="nav-drop-img-wrap">
        <img src="${getFirstImg(p)}" class="nav-drop-img" onerror="this.src='images/logo.png'" loading="lazy"/>
      </div>
      <div class="nav-drop-info">
        <div class="nav-drop-cat">${p.category}</div>
        <div class="nav-drop-name">${p.name}</div>
        <div class="nav-drop-price">${formatPrice(p.price)}</div>
      </div>
    </div>`).join('');
}

function clearNavDropSearch(){
  const inp = document.getElementById('navDropSearchInput');
  if(inp){ inp.value = ''; inp.focus(); }
  document.getElementById('navDropClear').style.display = 'none';
  navDropActiveCat = 'All';
  buildNavDropFilters();
  runNavDropSearch();
}

function launchNavDropSearch(){
  const q = document.getElementById('navDropSearchInput')?.value || '';
  closeNavSearch();
  openSearchPopup();
  setTimeout(()=>{
    const inp = document.getElementById('mainSearchInput');
    if(inp){ inp.value = q; runSearch(); }
  }, 200);
}

// Legacy stubs — kept so nothing breaks
function toggleHeroSearch(){ toggleNavSearch(); }
function initHeroSearch(){ buildNavDropFilters(); }
function runHeroSearch(){ runNavDropSearch(); }
function launchFullSearch(){ launchNavDropSearch(); }

function getFirstImg(p){
  if(Array.isArray(p.images)&&p.images.length) return p.images[0];
  return p.image || 'images/logo.png';
}

// ─── SLIDESHOW ENGINE ────────────────────────
const slideshowTimers = {};

function initSlideshows(){
  document.querySelectorAll('.product-slideshow').forEach(el=>{
    const id = el.dataset.pid;
    if(!id) return;
    const slides = el.querySelectorAll('.slide');
    if(slides.length <= 1) return;
    let idx = 0;
    const dots = el.querySelectorAll('.dot');
    clearInterval(slideshowTimers[id]);
    slideshowTimers[id] = setInterval(()=>{
      slides[idx].classList.remove('active');
      dots[idx]?.classList.remove('active');
      idx = (idx+1) % slides.length;
      slides[idx].classList.add('active');
      dots[idx]?.classList.add('active');
    }, 3200);
  });
}

// Override popupProductCard to support slideshows
function popupProductCard(p, i, closeFn){
  const stockLabel = {'in-stock':'In Stock','limited':'Limited','out-of-stock':'Out of Stock'}[p.stock]||'In Stock';
  const disabled = p.stock==='out-of-stock';
  const imgs = Array.isArray(p.images)&&p.images.length ? p.images : (p.image?[p.image]:[]);

  // Stock quantity display
  const qty = p.stockQty !== undefined ? p.stockQty : null;
  let qtyHtml = '';
  if(qty !== null){
    if(qty === 0){
      qtyHtml = `<span class="product-stock-qty out-of-stock">0 left</span>`;
    } else if(qty <= 5){
      qtyHtml = `<span class="product-stock-qty limited">Only ${qty} left</span>`;
    } else {
      qtyHtml = `<span class="product-stock-qty in-stock">${qty} in stock</span>`;
    }
  }

  let mediaHtml = '';
  if(imgs.length > 1){
    mediaHtml = `
      <div class="product-slideshow" data-pid="${p.id}">
        ${imgs.map((src,si)=>`
          <div class="slide ${si===0?'active':''}">
            <img src="${src}" alt="${p.name}" onerror="this.src='images/logo.png'" loading="lazy"/>
          </div>`).join('')}
        <div class="product-slideshow-dots">
          ${imgs.map((_,si)=>`<span class="dot ${si===0?'active':''}" onclick="event.stopPropagation()"></span>`).join('')}
        </div>
      </div>`;
  } else {
    mediaHtml = `<div class="product-img-wrap"><img src="${imgs[0]||'images/logo.png'}" alt="${p.name}" class="product-img" onerror="this.src='images/logo.png'" loading="lazy"/></div>`;
  }

  return `
    <div class="product-card" style="animation-delay:${i*0.04}s" onclick="${closeFn}(); openProductModal(${p.id})">
      ${p.badge?`<span class="product-badge">${p.badge}</span>`:''}
      ${mediaHtml}
      <div class="product-info">
        <div class="product-category">${p.category}</div>
        <div class="product-name">${p.name}</div>
        <div class="product-desc">${(p.description||'').replace(/<[^>]+>/g,'').substring(0,90)}…</div>
        <div class="product-footer">
          <div class="product-price">${formatPrice(p.price)}</div>
          <div class="product-stock ${p.stock||'in-stock'}">${stockLabel}</div>
        </div>
        ${qtyHtml}
      </div>
      <div class="product-social-proof">
        ${(()=>{ const sp=typeof getSocialProof==='function'?getSocialProof(p.id):{sold:0,viewing:0}; const avg=typeof getAvgRating==='function'?getAvgRating(p.id):0; const reviews=typeof getReviews==='function'?getReviews(p.id):[];
          let html='';
          if(avg>0) html+=`<span class="proof-hot">★ ${avg.toFixed(1)}</span><span class="star-count">(${reviews.length})</span><span style="color:var(--dark3)">·</span>`;
          if(sp.sold>0) html+=`<span class="proof-hot">🔥 ${sp.sold} sold</span>`;
          if(sp.viewing>1) html+=`<span style="color:var(--dark3)">·</span><span class="proof-eye">👁 ${sp.viewing} viewing</span>`;
          return html;
        })()}
      </div>
      <div class="card-actions" onclick="event.stopPropagation()">
        <button class="btn-add-cart" ${disabled?'disabled':''} onclick="addToCart(${p.id})">${disabled?'Out of Stock':'Add to Cart'}</button>
        <button class="btn-view-more" onclick="${closeFn}(); openProductModal(${p.id})">Details</button>
      </div>
    </div>`;
}


// ─── HOMEPAGE PRODUCT CARD ────────────────────
// Same appearance as popup cards but:
//   • No "Details" button
//   • Click opens openHomepageModal (shows name + stock + share only)
function homepageProductCard(p, i) {
  const stockLabel = {'in-stock':'In Stock','limited':'Limited','out-of-stock':'Out of Stock'}[p.stock]||'In Stock';
  const disabled   = p.stock==='out-of-stock';
  const imgs = Array.isArray(p.images)&&p.images.length ? p.images : (p.image?[p.image]:[]);

  const qty = p.stockQty !== undefined ? p.stockQty : null;
  let qtyHtml = '';
  if(qty !== null){
    if(qty === 0)         qtyHtml = `<span class="product-stock-qty out-of-stock">0 left</span>`;
    else if(qty <= 5)     qtyHtml = `<span class="product-stock-qty limited">Only ${qty} left</span>`;
    else                  qtyHtml = `<span class="product-stock-qty in-stock">${qty} in stock</span>`;
  }

  let mediaHtml = '';
  if(imgs.length > 1){
    mediaHtml = `
      <div class="product-slideshow" data-pid="${p.id}">
        ${imgs.map((src,si)=>`
          <div class="slide ${si===0?'active':''}">
            <img src="${src}" alt="${p.name}" onerror="this.src='images/logo.png'" loading="lazy"/>
          </div>`).join('')}
        <div class="product-slideshow-dots">
          ${imgs.map((_,si)=>`<span class="dot ${si===0?'active':''}" onclick="event.stopPropagation()"></span>`).join('')}
        </div>
      </div>`;
  } else {
    mediaHtml = `<div class="product-img-wrap"><img src="${imgs[0]||'images/logo.png'}" alt="${p.name}" class="product-img" onerror="this.src='images/logo.png'" loading="lazy"/></div>`;
  }

  return `
    <div class="product-card" style="animation-delay:${i*0.04}s" onclick="openHomepageModal(${p.id})">
      ${p.badge?`<span class="product-badge">${p.badge}</span>`:''}
      ${mediaHtml}
      <div class="product-info">
        <div class="product-category">${p.category}</div>
        <div class="product-name">${p.name}</div>
        <div class="product-desc">${(p.description||'').replace(/<[^>]+>/g,'').substring(0,90)}…</div>
        <div class="product-footer">
          <div class="product-price">${formatPrice(p.price)}</div>
          <div class="product-stock ${p.stock||'in-stock'}">${stockLabel}</div>
        </div>
        ${qtyHtml}
      </div>
      <div class="card-actions" onclick="event.stopPropagation()">
        <button class="btn-add-cart" ${disabled?'disabled':''} onclick="addToCart(${p.id})">${disabled?'Out of Stock':'Add to Cart'}</button>
      </div>
    </div>`;
}

// ─── HOMEPAGE MODAL ───────────────────────────
// Lightweight product modal for homepage: name + stock + share only
function openHomepageModal(productId) {
  const p = getProducts().find(x => x.id === productId);
  if (!p) return;
  const serial    = getProductSerial(p);
  const link      = getShareLink(p);
  const qty       = p.stockQty !== undefined ? p.stockQty : null;
  const stockLabel = {'in-stock':'In Stock','limited':'Limited Stock','out-of-stock':'Out of Stock'}[p.stock]||'In Stock';
  const disabled  = p.stock === 'out-of-stock';

  let qtyHtml = '';
  if(qty !== null){
    if(qty === 0)       qtyHtml = `<span class="product-stock-qty out-of-stock" style="font-size:13px;">0 left</span>`;
    else if(qty <= 5)   qtyHtml = `<span class="product-stock-qty limited" style="font-size:13px;">Only ${qty} left</span>`;
    else                qtyHtml = `<span class="product-stock-qty in-stock" style="font-size:13px;">${qty} in stock</span>`;
  }

  const imgs = Array.isArray(p.images)&&p.images.length ? p.images : (p.image?[p.image]:[]);
  let mediaHtml = '';
  if(imgs.length > 1){
    let slides = imgs.map((src,si)=>`<div class="modal-slide ${si===0?'active':''}"><img src="${src}" alt="${p.name}" onerror="this.src='images/logo.png'"/></div>`).join('');
    const totalSlides = imgs.length;
    const dots = Array.from({length:totalSlides},(_,si)=>`<span class="sdot ${si===0?'active':''}" onclick="setModalSlide(${si})"></span>`).join('');
    mediaHtml = `<div class="modal-slideshow" id="modalSlideshow">
      ${slides}
      ${totalSlides>1?`<button class="modal-slideshow-prev" onclick="event.stopPropagation();shiftModalSlide(-1)">‹</button>
      <button class="modal-slideshow-next" onclick="event.stopPropagation();shiftModalSlide(1)">›</button>
      <div class="modal-slideshow-nav">${dots}</div>`:''}
    </div>`;
  } else {
    mediaHtml = `<div class="modal-product-img-wrap"><img src="${imgs[0]||'images/logo.png'}" class="modal-product-img" onerror="this.src='images/logo.png'"/></div>`;
  }

  const waText = encodeURIComponent('🛒 *' + p.name + '*\n' + formatPrice(p.price) + '\n\nView & order here:\n' + link);
  const xText  = encodeURIComponent('Check out ' + p.name + ' — ' + formatPrice(p.price) + ' on Paramount E-mart');

  document.getElementById('modalBody').innerHTML = `
    <div class="modal-product-top">
      ${mediaHtml}
      <div class="modal-product-info">
        ${p.badge?`<div class="modal-badge">${p.badge}</div>`:''}
        <div class="modal-product-cat">${p.category} <span class="modal-serial">· ${serial}</span></div>
        <div class="modal-product-name">${p.name}</div>
        <div class="modal-product-price">${formatPrice(p.price)}</div>
        <div class="modal-product-stock ${p.stock||'in-stock'}">${stockLabel}</div>
        ${qtyHtml ? `<div style="margin:10px 0;">${qtyHtml}</div>` : ''}
        <div class="modal-divider"></div>
        <div class="modal-actions">
          <button class="modal-add-btn" ${disabled?'disabled':''} onclick="addToCart(${p.id}); closeModal();">
            ${disabled?'Out of Stock':'Add to Cart'}
          </button>
        </div>
        <div class="modal-divider" style="margin-top:16px;"></div>
        <div class="psp-head" style="padding:0;margin-bottom:12px;">
          <span class="psp-title">Share This Product</span>
        </div>
        <div class="psp-serial-row">
          <span class="psp-serial-label">Serial No.</span>
          <span class="psp-serial">${serial}</span>
        </div>
        <div class="psp-link-row">
          <input class="psp-link-input" id="pspLinkInput" type="text" value="${link}" readonly onclick="this.select()"/>
          <button class="psp-copy-btn" onclick="copyShareLink('${link.replace(/'/g,"\'")}')">Copy</button>
        </div>
        <div class="psp-channels">
          <a class="psp-channel psp-wa" href="https://wa.me/?text=${waText}" target="_blank" rel="noopener">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 2C6.477 2 2 6.477 2 12c0 1.89.525 3.66 1.438 5.168L2.07 21.5l4.43-1.393A9.953 9.953 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 12 2zm0 18a7.95 7.95 0 01-4.073-1.117l-.292-.174-3.03.953.947-2.96-.19-.305A7.96 7.96 0 014 12c0-4.411 3.589-8 8-8s8 3.589 8 8-3.589 8-8 8z"/></svg>
            WhatsApp
          </a>
          <a class="psp-channel psp-x" href="https://twitter.com/intent/tweet?text=${xText}&url=${encodeURIComponent(link)}" target="_blank" rel="noopener">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.747l7.73-8.835L1.254 2.25H8.08l4.259 5.63zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
            Post on X
          </a>
          <button class="psp-channel psp-copy2" onclick="copyShareLink('${link.replace(/'/g,"\'")}')">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
            Copy Link
          </button>
        </div>
      </div>
    </div>`;
  document.getElementById('productModal').classList.add('open');
  document.getElementById('modalOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  window._modalSlideIdx = 0;
}

// ─── PRODUCT MODAL ──────────────────────────

// Enhanced product modal with slideshow
window.openProductModal = function(productId){
  const p=getProducts().find(x=>x.id===productId);
  if(!p) return;
  const stockLabel={'in-stock':'In Stock','limited':'Limited Stock','out-of-stock':'Out of Stock'}[p.stock]||'In Stock';
  const disabled=p.stock==='out-of-stock';
  const imgs = Array.isArray(p.images)&&p.images.length ? p.images : (p.image?[p.image]:[]);

  let mediaHtml = '';
  const allMedia = [...imgs];
  if(p.video) allMedia.push({type:'video', src:p.video});

  if(allMedia.length > 1 || (allMedia.length===1 && p.video)){
    // full slideshow
    let slides = imgs.map((src,i)=>`
      <div class="modal-slide ${i===0?'active':''}">
        <img src="${src}" alt="${p.name}" onerror="this.src='images/logo.png'"/>
      </div>`).join('');
    if(p.video) slides += `<div class="modal-slide"><video controls style="width:100%;height:100%;object-fit:contain;background:#000;"><source src="${p.video}"/></video></div>`;
    const totalSlides = imgs.length + (p.video?1:0);
    const dots = Array.from({length:totalSlides},(_,i)=>`<span class="sdot ${i===0?'active':''}" onclick="setModalSlide(${i})"></span>`).join('');
    mediaHtml = `
      <div class="modal-slideshow" id="modalSlideshow">
        ${slides}
        ${totalSlides>1?`
          <button class="modal-slideshow-prev" onclick="event.stopPropagation(); shiftModalSlide(-1)">‹</button>
          <button class="modal-slideshow-next" onclick="event.stopPropagation(); shiftModalSlide(1)">›</button>
          <div class="modal-slideshow-nav">${dots}</div>`:''}
      </div>`;
  } else if(p.video){
    mediaHtml=`<div class="modal-media-wrap"><video controls class="modal-video" poster="${imgs[0]||'images/logo.png'}"><source src="${p.video}"/>Your browser does not support video.</video></div>`;
  } else {
    mediaHtml=`<div class="modal-product-img-wrap"><img src="${imgs[0]||'images/logo.png'}" class="modal-product-img" onerror="this.src='images/logo.png'"/></div>`;
  }

  document.getElementById('modalBody').innerHTML=`
    <div class="modal-product-top">
      ${mediaHtml}
      <div class="modal-product-info">
        ${p.badge?`<div class="modal-badge">${p.badge}</div>`:''}
        <div class="modal-product-cat">${p.category} <span class="modal-serial">· ${getProductSerial(p)}</span></div>
        <div class="modal-product-name">${p.name}</div>
        <div class="modal-product-price">${formatPrice(p.price)}</div>
        <div class="modal-product-stock ${p.stock}">${stockLabel}</div>
        <div class="modal-divider"></div>
        <p class="modal-product-desc">${p.description||''}</p>
        <div class="modal-actions">
          <button class="modal-add-btn" ${disabled?'disabled':''} onclick="addToCart(${p.id}); closeModal();">${disabled?'Out of Stock':'Add to Cart'}</button>
          <button class="modal-share-btn" onclick="shareProduct(${p.id})">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>Share
          </button>
        </div>
        <a class="whatsapp-order-btn" onclick="closeModal(); addToCart(${p.id}); setTimeout(orderViaWhatsApp,300);">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 2C6.477 2 2 6.477 2 12c0 1.89.525 3.66 1.438 5.168L2.07 21.5l4.43-1.393A9.953 9.953 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 12 2zm0 18a7.95 7.95 0 01-4.073-1.117l-.292-.174-3.03.953.947-2.96-.19-.305A7.96 7.96 0 014 12c0-4.411 3.589-8 8-8s8 3.589 8 8-3.589 8-8 8z"/></svg>
          Order via WhatsApp
        </a>
      </div>
    </div>
    ${typeof renderAlsoBought === 'function' ? renderAlsoBought(p.id) : ''}
    ${typeof renderReviewsSection === 'function' ? renderReviewsSection(p.id) : ''}
  `;
  document.getElementById('productModal').classList.add('open');
  document.getElementById('modalOverlay').classList.add('open');
  document.body.style.overflow='hidden';
  window._modalSlideIdx = 0;
};

window._modalSlideIdx = 0;
function shiftModalSlide(dir){
  const container = document.getElementById('modalSlideshow');
  if(!container) return;
  const slides = container.querySelectorAll('.modal-slide');
  const dots = container.querySelectorAll('.sdot');
  const n = slides.length;
  slides[window._modalSlideIdx]?.classList.remove('active');
  dots[window._modalSlideIdx]?.classList.remove('active');
  window._modalSlideIdx = (window._modalSlideIdx + dir + n) % n;
  slides[window._modalSlideIdx]?.classList.add('active');
  dots[window._modalSlideIdx]?.classList.add('active');
}
function setModalSlide(i){
  const container = document.getElementById('modalSlideshow');
  if(!container) return;
  const slides = container.querySelectorAll('.modal-slide');
  const dots = container.querySelectorAll('.sdot');
  slides[window._modalSlideIdx]?.classList.remove('active');
  dots[window._modalSlideIdx]?.classList.remove('active');
  window._modalSlideIdx = i;
  slides[i]?.classList.add('active');
  dots[i]?.classList.add('active');
}

// (Hero search is also initialized in main DOMContentLoaded above)
window._heroSearchReady = true;

// ══════════════════════════════════════════════════════════
//  ENHANCEMENTS — Reviews, Promo Codes, Delivery Fees,
//  WhatsApp Orders, Social Proof
// ══════════════════════════════════════════════════════════


function copyPromoCode(code) {
  navigator.clipboard.writeText(code).then(() => showToast('Code ' + code + ' copied!')).catch(() => {});
  const inp = document.getElementById('promoCodeInput');
  if (inp) { inp.value = code; applyPromoCode(); }
}

// ── PROMO CODES ──────────────────────────────────────────
const PROMO_CODES = {
  'PARAMOUNT10': { type: 'percent',  value: 10, label: '10% off'  },
  'PARAMOUNT20': { type: 'percent',  value: 20, label: '20% off'  },
  'WELCOME5':    { type: 'percent',  value: 5,  label: '5% off'   },
  'FREESHIP':    { type: 'shipping', value: 0,  label: 'Free delivery' },
  'FLAT5000':    { type: 'fixed',    value: 5000, label: '₦5,000 off' },
};

let _activePromo = null;

function applyPromoCode() {
  var inp = document.getElementById('promoCodeInput');
  var fb  = document.getElementById('promoFeedback');
  if (!inp || !fb) return;
  var code = inp.value.trim().toUpperCase();
  if (!code) { fb.textContent = 'Please enter a code.'; fb.className = 'promo-feedback error'; return; }

  if (typeof pesVerifying !== 'function') {
    // fallback if loader not available
    var promo = PROMO_CODES[code];
    if (!promo) { _activePromo = null; fb.textContent = '✗ Invalid code.'; fb.className = 'promo-feedback error'; updateCheckoutTotals(); return; }
    _activePromo = Object.assign({ code: code }, promo);
    fb.textContent = '✓ Code applied — ' + promo.label + '!'; fb.className = 'promo-feedback success';
    showToast('Promo applied: ' + promo.label); updateCheckoutTotals(); return;
  }

  pesVerifying('Checking Promo Code…', function(done) {
    var promo = PROMO_CODES[code];
    if (!promo) {
      _activePromo = null;
      done('Code Not Found', 'That promo code is invalid or has expired.', function() {
        fb.textContent = '✗ Invalid code. Try PARAMOUNT10 or WELCOME5.';
        fb.className = 'promo-feedback error';
        updateCheckoutTotals();
      });
      return;
    }
    _activePromo = Object.assign({ code: code }, promo);
    done('Promo Applied! 🎉', promo.label + ' has been added to your order.', function() {
      fb.textContent = '✓ ' + promo.label + ' applied!';
      fb.className = 'promo-feedback success';
      updateCheckoutTotals();
    });
  }, { icon: '🎟', minMs: 2000, maxMs: 3400 });
}

function getPromoDiscount(subtotal) {
  if (!_activePromo) return 0;
  if (_activePromo.type === 'percent')  return Math.round(subtotal * _activePromo.value / 100);
  if (_activePromo.type === 'fixed')    return Math.min(_activePromo.value, subtotal);
  if (_activePromo.type === 'shipping') return 0; // handled separately
  return 0;
}

// ── DELIVERY FEES ─────────────────────────────────────────
// Delivery origin: Uyo, Akwa Ibom State
// Domestic: nationwide delivery from Uyo
// International: China (wholesale/import items)
const DELIVERY_ZONES = [
  // ── LOCAL (Uyo & Akwa Ibom) ──────────────────────────────
  { zone: 'Uyo (Akwa Ibom) — Local',    fee: 500,   label: 'Within Uyo & environs',           type: 'local'    },
  { zone: 'Other Akwa Ibom Towns',      fee: 1500,  label: 'Eket, Ikot Ekpene, Oron, etc.',   type: 'local'    },
  // ── SOUTH-SOUTH ──────────────────────────────────────────
  { zone: 'Port Harcourt (Rivers)',      fee: 3500,  label: '1–2 business days',               type: 'domestic' },
  { zone: 'Calabar (Cross River)',       fee: 3500,  label: '1–2 business days',               type: 'domestic' },
  { zone: 'Warri / Asaba (Delta)',       fee: 4500,  label: '2–3 business days',               type: 'domestic' },
  { zone: 'Benin City (Edo)',            fee: 4500,  label: '2–3 business days',               type: 'domestic' },
  { zone: 'Yenagoa (Bayelsa)',           fee: 4000,  label: '2–3 business days',               type: 'domestic' },
  // ── SOUTH-EAST ───────────────────────────────────────────
  { zone: 'Aba / Umuahia (Abia)',        fee: 3500,  label: '1–2 business days',               type: 'domestic' },
  { zone: 'Enugu State',                fee: 4000,  label: '2–3 business days',               type: 'domestic' },
  { zone: 'Onitsha / Awka (Anambra)',   fee: 4000,  label: '2–3 business days',               type: 'domestic' },
  { zone: 'Owerri (Imo)',               fee: 4000,  label: '2–3 business days',               type: 'domestic' },
  // ── SOUTH-WEST ───────────────────────────────────────────
  { zone: 'Lagos (Island / Mainland)',   fee: 6000,  label: '3–4 business days',               type: 'domestic' },
  { zone: 'Ibadan (Oyo)',               fee: 6500,  label: '3–4 business days',               type: 'domestic' },
  { zone: 'Abeokuta (Ogun)',            fee: 6500,  label: '3–4 business days',               type: 'domestic' },
  { zone: 'Akure (Ondo)',               fee: 6000,  label: '3–4 business days',               type: 'domestic' },
  { zone: 'Osogbo (Osun)',              fee: 6500,  label: '3–4 business days',               type: 'domestic' },
  // ── FCT & MIDDLE BELT ─────────────────────────────────────
  { zone: 'Abuja (FCT)',                fee: 6500,  label: '3–4 business days',               type: 'domestic' },
  { zone: 'Makurdi (Benue)',            fee: 5500,  label: '3–4 business days',               type: 'domestic' },
  { zone: 'Lokoja (Kogi)',              fee: 5500,  label: '3–4 business days',               type: 'domestic' },
  // ── NORTH ────────────────────────────────────────────────
  { zone: 'Kano State',                 fee: 8000,  label: '4–5 business days',               type: 'domestic' },
  { zone: 'Kaduna State',               fee: 8000,  label: '4–5 business days',               type: 'domestic' },
  { zone: 'Jos (Plateau)',              fee: 7500,  label: '4–5 business days',               type: 'domestic' },
  { zone: 'Minna (Niger)',              fee: 7500,  label: '4–5 business days',               type: 'domestic' },
  { zone: 'Other North States',         fee: 9000,  label: '5–7 business days',               type: 'domestic' },
  // ── INTERNATIONAL (China) ─────────────────────────────────
  { zone: '🇨🇳 China — Sea Freight (Budget)', fee: 0, label: '25–40 days · Contact for quote', type: 'international', contactOnly: true },
  { zone: '🇨🇳 China — Air Freight (Express)', fee: 0, label: '7–14 days · Contact for quote', type: 'international', contactOnly: true },
];

let _deliveryFee = 500; // default: Uyo local

// ── COUNTRY / STATE DATA ──────────────────────────────────
const _CHECKOUT_COUNTRIES = [
  { code: 'NG', name: 'Nigeria', hasStates: true },
  { code: 'GH', name: 'Ghana' },
  { code: 'KE', name: 'Kenya' },
  { code: 'ZA', name: 'South Africa' },
  { code: 'UG', name: 'Uganda' },
  { code: 'TZ', name: 'Tanzania' },
  { code: 'ET', name: 'Ethiopia' },
  { code: 'SN', name: 'Senegal' },
  { code: 'CI', name: "Côte d'Ivoire" },
  { code: 'CM', name: 'Cameroon' },
  { code: 'GB', name: 'United Kingdom' },
  { code: 'US', name: 'United States' },
  { code: 'CA', name: 'Canada' },
  { code: 'DE', name: 'Germany' },
  { code: 'FR', name: 'France' },
  { code: 'AE', name: 'United Arab Emirates' },
  { code: 'CN', name: 'China' },
  { code: 'IN', name: 'India' },
  { code: 'OTHER', name: 'Other Country' },
];

const _NG_STATES = [
  'Abia','Adamawa','Akwa Ibom','Anambra','Bauchi','Bayelsa','Benue','Borno',
  'Cross River','Delta','Ebonyi','Edo','Ekiti','Enugu','FCT — Abuja',
  'Gombe','Imo','Jigawa','Kaduna','Kano','Katsina','Kebbi','Kogi',
  'Kwara','Lagos','Nasarawa','Niger','Ogun','Ondo','Osun','Oyo',
  'Plateau','Rivers','Sokoto','Taraba','Yobe','Zamfara',
];

// Map Nigerian states → nearest DELIVERY_ZONES index
const _NG_STATE_ZONE = {
  'Akwa Ibom':      0, // Uyo local (default to local; city field refines)
  'Cross River':    3,
  'Rivers':         2,
  'Bayelsa':        6,
  'Delta':          4,
  'Edo':            5,
  'Abia':           7,
  'Imo':            10,
  'Anambra':        9,
  'Enugu':          8,
  'Ebonyi':         8,
  'Lagos':          11,
  'Ogun':           13,
  'Oyo':            12,
  'Osun':           14,
  'Ondo':           13,
  'Ekiti':          13,
  'FCT — Abuja':    15,
  'Benue':          16,
  'Kogi':           17,
  'Nasarawa':       15,
  'Kano':           18,
  'Kaduna':         19,
  'Plateau':        20,
  'Niger':          21,
  'Adamawa':        22,
  'Borno':          22,
  'Gombe':          22,
  'Yobe':           22,
  'Bauchi':         22,
  'Taraba':         22,
  'Jigawa':         22,
  'Katsina':        22,
  'Kebbi':          22,
  'Sokoto':         22,
  'Zamfara':        22,
  'Kwara':          17,
};

function _populateCountrySelect() {
  const sel = document.getElementById('chkCountry');
  if (!sel || sel.options.length > 1) return; // already populated
  _CHECKOUT_COUNTRIES.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.code;
    opt.textContent = c.name;
    sel.appendChild(opt);
  });
  // Default to Nigeria
  sel.value = 'NG';
  onCountryChange();
}

function onCountryChange() {
  const sel    = document.getElementById('chkCountry');
  const code   = sel ? sel.value : '';
  const stateGrp = document.getElementById('chkStateGroup');
  const stateSel = document.getElementById('chkState');
  const postalGrp = document.getElementById('chkPostalGroup');

  if (code === 'NG') {
    // Show state select, populate with Nigerian states
    if (stateGrp) stateGrp.style.display = '';
    if (stateSel) {
      stateSel.innerHTML = '<option value="">— Select State —</option>';
      _NG_STATES.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s;
        opt.textContent = s;
        stateSel.appendChild(opt);
      });
    }
    if (postalGrp) postalGrp.style.display = 'none';
    // Set local delivery fee until state is picked
    _deliveryFee = 500;
  } else if (code === 'CN') {
    // China — international freight
    if (stateGrp) stateGrp.style.display = 'none';
    if (postalGrp) postalGrp.style.display = '';
    _deliveryFee = 0; // contact only
    _showDeliveryNote('✈ International freight — <strong>contact us for a shipping quote</strong>.', true);
    updateCheckoutTotals();
    return;
  } else if (code) {
    // Other international country
    if (stateGrp) stateGrp.style.display = 'none';
    if (postalGrp) postalGrp.style.display = '';
    _deliveryFee = 0;
    _showDeliveryNote('✈ International delivery — <strong>contact us for a shipping quote</strong>.', true);
    updateCheckoutTotals();
    return;
  } else {
    if (stateGrp) stateGrp.style.display = 'none';
    if (postalGrp) postalGrp.style.display = 'none';
  }
  _showDeliveryNote('', false);
  updateCheckoutTotals();
}

function onStateChange() {
  const stateSel = document.getElementById('chkState');
  const state    = stateSel ? stateSel.value : '';
  if (!state) return;

  const zoneIdx = _NG_STATE_ZONE[state];
  if (zoneIdx !== undefined) {
    const zone = DELIVERY_ZONES[zoneIdx];
    _deliveryFee = zone ? zone.fee : 500;
    if (zone) {
      const typeLabel = zone.type === 'local' ? '🏠 Local delivery' : '🚚 Nationwide delivery';
      _showDeliveryNote(typeLabel + ': <strong>' + (zone.fee === 0 ? 'Free' : formatPrice(zone.fee)) + '</strong> &nbsp;·&nbsp; <span style="color:var(--gray);font-size:10px;">' + zone.label + '</span>', false);
    }
  } else {
    _deliveryFee = 9000; // far north fallback
    _showDeliveryNote('🚚 Nationwide delivery: <strong>' + formatPrice(9000) + '</strong> &nbsp;·&nbsp; <span style="color:var(--gray);font-size:10px;">5–7 business days</span>', false);
  }
  updateCheckoutTotals();
}

function _showDeliveryNote(html, isContact) {
  const disp = document.getElementById('deliveryFeeDisplay');
  if (!disp) return;
  if (!html) { disp.innerHTML = ''; return; }
  if (isContact) {
    disp.innerHTML = '📞 ' + html + ' — <a href="#" onclick="closeCheckout();openContactPopup();return false;" style="color:#4caf50;font-weight:600;">Contact us</a>';
  } else {
    disp.innerHTML = html;
  }
}

function updateDeliveryFee() {
  const sel = document.getElementById('deliveryZoneSelect');
  if (!sel) return;
  const zoneIdx = parseInt(sel.value);
  const zone = DELIVERY_ZONES[zoneIdx];
  _deliveryFee = zone ? zone.fee : 0;
  const disp = document.getElementById('deliveryFeeDisplay');
  if (disp) {
    if (zone && zone.contactOnly) {
      disp.innerHTML = '📞 <strong>' + zone.label + '</strong> — <a href="#" onclick="closeCheckout();openContactPopup();return false;" style="color:#4caf50;font-weight:600;">Contact us to arrange</a>';
    } else if (_activePromo && _activePromo.type === 'shipping') {
      disp.innerHTML = 'Delivery: <strong style="color:#4caf50;">FREE (promo applied)</strong>';
    } else if (zone) {
      const feeText = zone.fee === 0 ? 'Free' : formatPrice(zone.fee);
      const typeLabel = zone.type === 'local' ? '🏠 Local delivery' : zone.type === 'international' ? '✈ International' : '🚚 Nationwide';
      disp.innerHTML = typeLabel + ': <strong>' + feeText + '</strong> &nbsp;·&nbsp; <span style="color:var(--gray);font-size:10px;">' + (zone.label || '') + '</span>';
    }
  }
  updateCheckoutTotals();
}

function updateCheckoutTotals() {
  const count = cart.reduce((a, b) => a + b.qty, 0);
  const rawTotal = cart.reduce((a, b) => a + b.price * b.qty, 0);
  const { discountedTotal, tier } = applyBulkDiscount(rawTotal, count);
  const promoDisc = getPromoDiscount(discountedTotal);
  const actualDelivery = (_activePromo && _activePromo.type === 'shipping') ? 0 : _deliveryFee;
  const grandTotal = discountedTotal - promoDisc + actualDelivery;

  const el = document.getElementById('summaryTotal');
  if (el) {
    let html = '';
    if (tier || promoDisc || actualDelivery) {
      html += '<div style="font-size:11px;color:var(--gray);margin-bottom:6px;">';
      html += '<div style="display:flex;justify-content:space-between;"><span>Subtotal</span><span>' + formatPrice(rawTotal) + '</span></div>';
      if (tier) html += '<div style="display:flex;justify-content:space-between;color:#4caf50;"><span>Bulk discount (' + tier.discount + '%)</span><span>−' + formatPrice(rawTotal - discountedTotal) + '</span></div>';
      if (promoDisc) html += '<div style="display:flex;justify-content:space-between;color:#ffb300;"><span>Promo (' + (_activePromo && _activePromo.code) + ')</span><span>−' + formatPrice(promoDisc) + '</span></div>';
      html += '<div style="display:flex;justify-content:space-between;"><span>Delivery</span><span>' + (actualDelivery ? formatPrice(actualDelivery) : '<span style="color:#4caf50">FREE</span>') + '</span></div>';
      html += '</div>';
    }
    html += '<div style="font-family:var(--font-display);font-size:24px;font-weight:300;margin-top:8px;">' + formatPrice(grandTotal) + '</div>';
    el.innerHTML = html;
  }
  return { grandTotal, promoDisc, actualDelivery };
}

// ── WHATSAPP ORDER ────────────────────────────────────────
function orderViaWhatsApp() {
  const phone = '2349160439848'; // set your WhatsApp number here
  const items = cart.map(i => `• ${i.name} ×${i.qty} — ${formatPrice(i.price * i.qty)}`).join('\n');
  const rawTotal = cart.reduce((a, b) => a + b.price * b.qty, 0);
  const { discountedTotal } = applyBulkDiscount(rawTotal, cart.reduce((a,b)=>a+b.qty,0));
  const msg = encodeURIComponent(
    `Hello Paramount E-mart! 👋\n\nI'd like to order:\n\n${items}\n\n` +
    `Total: ${formatPrice(discountedTotal)}\n\n` +
    `Please confirm availability and delivery details. Thank you!`
  );
  window.open(`https://wa.me/${phone}?text=${msg}`, '_blank');
}

// ── PRODUCT REVIEWS ───────────────────────────────────────
function getReviews(productId) {
  try {
    return JSON.parse(localStorage.getItem('pes_reviews_' + productId) || '[]');
  } catch { return []; }
}
function saveReview(productId, review) {
  const reviews = getReviews(productId);
  reviews.unshift(review);
  localStorage.setItem('pes_reviews_' + productId, JSON.stringify(reviews.slice(0, 50)));
}
function getAvgRating(productId) {
  const reviews = getReviews(productId);
  if (!reviews.length) return 0;
  return reviews.reduce((a, b) => a + b.rating, 0) / reviews.length;
}
function renderStars(rating, size) {
  size = size || 16;
  const full  = Math.floor(rating);
  const half  = rating - full >= 0.5 ? 1 : 0;
  const empty = 5 - full - half;
  let s = '';
  for (let i = 0; i < full;  i++) s += '★';
  if (half)                        s += '½';
  for (let i = 0; i < empty; i++) s += '☆';
  return s;
}

let _reviewPickedStars = 0;

function renderReviewsSection(productId) {
  const reviews = getReviews(productId);
  const avg = getAvgRating(productId);
  const count = reviews.length;
  _reviewPickedStars = 0;

  return `
    <div class="reviews-section" id="reviewsSection">
      <div class="reviews-header">
        <div class="reviews-title">Customer Reviews</div>
        <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
          ${count > 0 ? `
            <div class="reviews-summary">
              <div class="reviews-avg">${avg.toFixed(1)}</div>
              <div class="reviews-stars">
                <div class="stars-row">${renderStars(avg)}</div>
                <div class="reviews-count">${count} review${count !== 1 ? 's' : ''}</div>
              </div>
            </div>` : ''}
          <button class="write-review-btn" onclick="toggleReviewForm(${productId})">Write a Review</button>
        </div>
      </div>

      <div class="review-form" id="reviewForm_${productId}" style="display:none;">
        <h4>Share Your Experience</h4>
        <div class="star-picker" id="starPicker_${productId}">
          ${[1,2,3,4,5].map(n => `<span class="sp-star" onclick="pickStar(${n},${productId})" data-val="${n}">★</span>`).join('')}
        </div>
        <input class="review-name-input" id="reviewName_${productId}" placeholder="Your name (e.g. Chukwudi A.)" maxlength="40"/>
        <textarea class="review-text-input" id="reviewText_${productId}" placeholder="Tell others about this product — quality, delivery, value…" maxlength="400"></textarea>
        <div style="display:flex;gap:10px;align-items:center;">
          <button class="submit-review-btn" onclick="submitReview(${productId})">Post Review</button>
          <button onclick="toggleReviewForm(${productId})" style="background:none;border:none;color:var(--gray);font-size:11px;cursor:pointer;font-family:var(--font-body);">Cancel</button>
        </div>
      </div>

      <div class="review-list" id="reviewList_${productId}">
        ${count === 0
          ? '<div class="no-reviews">No reviews yet — be the first to share your experience!</div>'
          : reviews.map(r => `
            <div class="review-card">
              <div class="review-card-head">
                <div>
                  <div class="review-author">${r.author}</div>
                  <div class="review-date">${r.date}</div>
                </div>
                <div class="review-rating">${'★'.repeat(r.rating)}${'☆'.repeat(5-r.rating)}</div>
              </div>
              <div class="review-body">${r.text}</div>
              ${r.verified ? '<div class="review-verified">✓ Verified Purchase</div>' : ''}
            </div>`).join('')}
      </div>
    </div>`;
}

function toggleReviewForm(productId) {
  const form = document.getElementById('reviewForm_' + productId);
  if (form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

function pickStar(n, productId) {
  _reviewPickedStars = n;
  const stars = document.querySelectorAll('#starPicker_' + productId + ' .sp-star');
  stars.forEach((s, i) => s.classList.toggle('selected', i < n));
}

function submitReview(productId) {
  var nameEl = document.getElementById('reviewName_' + productId);
  var textEl = document.getElementById('reviewText_' + productId);
  var name = (nameEl ? nameEl.value : '').trim();
  var text = (textEl ? textEl.value : '').trim();
  if (!_reviewPickedStars) { showToast('Please select a star rating'); return; }
  if (!name) { showToast('Please enter your name'); return; }
  if (text.length < 10) { showToast('Please write at least 10 characters'); return; }

  if (typeof pesVerifying !== 'function') {
    var r = { author: name, rating: _reviewPickedStars, text: text, date: new Date().toLocaleDateString('en-NG',{day:'numeric',month:'short',year:'numeric'}), verified: false };
    saveReview(productId, r);
    var s = document.getElementById('reviewsSection');
    if (s) s.outerHTML = renderReviewsSection(productId);
    showToast('Review posted — thank you!'); return;
  }

  pesVerifying('Submitting Your Review…', function(done) {
    var review = {
      author: name, rating: _reviewPickedStars, text: text,
      date: new Date().toLocaleDateString('en-NG', { day:'numeric', month:'short', year:'numeric' }),
      verified: false
    };
    saveReview(productId, review);
    done('Review Posted! ⭐', 'Thank you, ' + name + '! Your review has been published.', function() {
      var section = document.getElementById('reviewsSection');
      if (section) section.outerHTML = renderReviewsSection(productId);
    });
  }, { icon: '⭐', minMs: 2200, maxMs: 3600 });
}

// ── SOCIAL PROOF DATA ─────────────────────────────────────
// Seeded view counts and sold counts per product (realistic)
const _socialProof = {
  1:  { sold: 147, viewing: 3 },
  2:  { sold: 89,  viewing: 1 },
  3:  { sold: 54,  viewing: 2 },
  4:  { sold: 71,  viewing: 1 },
  5:  { sold: 38,  viewing: 1 },
  6:  { sold: 203, viewing: 5 },
  7:  { sold: 29,  viewing: 2 },
  8:  { sold: 178, viewing: 4 },
  9:  { sold: 42,  viewing: 1 },
  10: { sold: 33,  viewing: 1 },
  11: { sold: 67,  viewing: 2 },
  12: { sold: 91,  viewing: 2 },
  13: { sold: 124, viewing: 3 },
  14: { sold: 58,  viewing: 2 },
  15: { sold: 44,  viewing: 1 },
  16: { sold: 37,  viewing: 1 },
  17: { sold: 29,  viewing: 1 },
  18: { sold: 22,  viewing: 1 },
};

function getSocialProof(productId) {
  const base = _socialProof[productId] || { sold: 12, viewing: 1 };
  // Add small random variance so it feels live
  const extraViewing = Math.floor(Math.random() * 3);
  return { sold: base.sold, viewing: base.viewing + extraViewing };
}

// ══════════════════════════════════════════════════════════
//  PAYMENT DROPDOWN
// ══════════════════════════════════════════════════════════

const _PM_LOGOS = {
  flutterwave: `<svg width="22" height="22" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg"><rect width="200" height="200" rx="40" fill="#F5A623"/><path d="M45 80 Q70 50 100 80 Q130 110 155 80" stroke="#fff" stroke-width="18" fill="none" stroke-linecap="round"/><path d="M45 110 Q70 80 100 110 Q130 140 155 110" stroke="#fff" stroke-width="18" fill="none" stroke-linecap="round"/><path d="M45 140 Q70 110 100 140 Q130 170 155 140" stroke="#fff" stroke-width="14" fill="none" stroke-linecap="round" opacity="0.7"/></svg>`,
  opay:        `<svg width="22" height="22" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg"><rect width="200" height="200" rx="40" fill="#00BF63"/><circle cx="100" cy="90" r="42" fill="none" stroke="#fff" stroke-width="18"/><rect x="86" y="132" width="28" height="36" rx="6" fill="#fff"/></svg>`,
  crypto:      `<svg width="22" height="22" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg"><rect width="200" height="200" rx="40" fill="#F7931A"/><text x="100" y="138" font-size="110" text-anchor="middle" fill="#fff" font-family="Arial" font-weight="bold">&#8383;</text></svg>`,
};
const _PM_SUBS = {
  flutterwave: 'Cards · Mobile Money · Bank',
  opay:        'OPay Wallet · Bank · USSD',
  crypto:      'USDT · BTC · ETH',
};
const _PM_NAMES = { flutterwave: 'Flutterwave', opay: 'OPay', crypto: 'Crypto' };

function togglePmDropdown() {
  var dd = document.getElementById('pmDropdown');
  if (!dd) return;
  dd.classList.toggle('open');
  // Close when clicking outside
  if (dd.classList.contains('open')) {
    setTimeout(function() {
      document.addEventListener('click', _closePmOnOutside, { once: true });
    }, 0);
  }
}
function _closePmOnOutside(e) {
  var dd = document.getElementById('pmDropdown');
  if (dd && !dd.contains(e.target)) dd.classList.remove('open');
}

function choosePmGateway(gateway, e) {
  if (e) e.stopPropagation();
  // Update selected display
  var logo = document.getElementById('pmDropLogo');
  var name = document.getElementById('pmDropName');
  var sub  = document.getElementById('pmDropSub');
  if (logo) logo.innerHTML = _PM_LOGOS[gateway] || '';
  if (name) name.textContent = _PM_NAMES[gateway] || gateway;
  if (sub)  sub.textContent  = _PM_SUBS[gateway]  || '';
  // Update check marks
  ['flutterwave','opay','crypto'].forEach(function(gw) {
    var chk = document.getElementById('pmCheck_' + gw);
    if (chk) chk.textContent = gw === gateway ? '✓' : '';
  });
  // Mark selected item
  document.querySelectorAll('.pm-drop-item').forEach(function(el) {
    el.classList.toggle('selected', el.getAttribute('data-gateway') === gateway);
  });
  // Close dropdown
  var dd = document.getElementById('pmDropdown');
  if (dd) dd.classList.remove('open');
  // Delegate to existing selectPaymentMethod
  selectPaymentMethod(gateway, null);
}

// ══════════════════════════════════════════════════════════
//  ORDER HISTORY LOOKUP
// ══════════════════════════════════════════════════════════

function lookupOrders() {
  var email = (document.getElementById('orderHistoryEmail').value || '').trim().toLowerCase();
  var results = document.getElementById('orderHistoryResults');
  if (!email || !email.includes('@')) {
    results.innerHTML = '<div class="oh-no-orders">Please enter a valid email address.</div>';
    return;
  }
  var orders = getOrders ? getOrders() : [];
  var matched = orders.filter(function(o) {
    return (o.email || '').toLowerCase() === email;
  });
  if (!matched.length) {
    results.innerHTML = '<div class="oh-no-orders">No orders found for <strong>' + email + '</strong>.<br>Try the email you used at checkout, or <a href="#" onclick="openContactPopup();return false;" style="color:#fff;">contact us</a> for help.</div>';
    return;
  }
  results.innerHTML = matched.slice(0).reverse().map(function(o) {
    var items = (o.items || []).map(function(i) { return i.name + ' ×' + i.qty; }).join(', ');
    var trackLink = o.trackingId ? '<a class="oh-track-btn" href="tracking.html?id=' + o.trackingId + '">Track →</a>' : '';
    return '<div class="oh-order-card">' +
      '<div class="oh-order-head">' +
        '<div><div class="oh-order-id">' + o.id + '</div><div class="oh-order-date">' + (o.date||'') + '</div></div>' +
        '<span class="oh-order-status">' + (o.status||'paid').toUpperCase() + '</span>' +
      '</div>' +
      '<div class="oh-order-items">' + items + '</div>' +
      '<div class="oh-order-total"><span>Total</span><span>' + formatPrice(o.total) + '</span>' + trackLink + '</div>' +
    '</div>';
  }).join('');
}

// ══════════════════════════════════════════════════════════
//  ABANDONED CART — capture email early, save intent
// ══════════════════════════════════════════════════════════

(function() {
  // When email field is blurred in checkout, save cart snapshot
  document.addEventListener('DOMContentLoaded', function() {
    var emailField = document.getElementById('chkEmail');
    if (!emailField) return;
    emailField.addEventListener('blur', function() {
      var email = emailField.value.trim();
      if (!email || !email.includes('@')) return;
      var snapshot = {
        email: email,
        items: JSON.parse(localStorage.getItem('pes_cart') || '[]'),
        time: Date.now(),
        page: window.location.href
      };
      localStorage.setItem('pes_abandoned_cart', JSON.stringify(snapshot));
    });
    // Clear abandoned cart on successful payment (done in _onPaymentSuccess)
  });
})();

// ══════════════════════════════════════════════════════════
//  CUSTOMERS ALSO BOUGHT
// ══════════════════════════════════════════════════════════

function renderAlsoBought(currentProductId) {
  var prods = getProducts ? getProducts() : [];
  var current = prods.find(function(p) { return p.id === currentProductId; });
  if (!current || prods.length < 2) return '';
  // Get same category products, fallback to random
  var samecat = prods.filter(function(p) { return p.id !== currentProductId && p.category === current.category; });
  var others  = prods.filter(function(p) { return p.id !== currentProductId && p.category !== current.category; });
  var pool = samecat.concat(others);
  // Shuffle for variety
  for (var i = pool.length - 1; i > 0; i--) {
    var j = Math.floor(Math.random() * (i + 1));
    var tmp = pool[i]; pool[i] = pool[j]; pool[j] = tmp;
  }
  var picks = pool.slice(0, 4);
  if (!picks.length) return '';
  return '<div class="also-bought-section">' +
    '<div class="also-bought-title">Customers Also Bought</div>' +
    '<div class="also-bought-grid">' +
    picks.map(function(p) {
      var disabled = p.stock === 'out-of-stock' || p.stockQty === 0;
      return '<div class="also-bought-card" onclick="closeModal();setTimeout(function(){openProductModal(' + p.id + ')},80)">' +
        '<div class="also-bought-img">' + pImg(p.images ? p.images[0] : p.image, p.name, 'also-img') + '</div>' +
        '<div class="also-bought-info">' +
          '<div class="also-bought-name">' + p.name + '</div>' +
          '<div class="also-bought-price">' + formatPrice(p.price) + '</div>' +
          '<button class="also-bought-add" ' + (disabled ? 'disabled' : '') + ' onclick="event.stopPropagation();addToCart(' + p.id + ')">' +
            (disabled ? 'Out of Stock' : '+ Cart') +
          '</button>' +
        '</div>' +
      '</div>';
    }).join('') +
    '</div></div>';
}
