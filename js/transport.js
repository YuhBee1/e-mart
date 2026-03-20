/* =============================================
   PARAMOUNT E-STORE — TRANSPORT MONITOR
   Live shipment tracking engine with
   real-time position simulation
   ============================================= */

const TRANSPORT_TICK_MS = 4000; // update every 4 seconds
let _transportTimers = {}; // { shipmentId: intervalId }
let _transportListeners = []; // callbacks for UI updates

// ── LIVE POSITION ENGINE ─────────────────────
// Interpolates position along route over time
function getLivePosition(shipment) {
  const now = Date.now();
  const key = 'pes_transport_live_' + shipment.id;
  let live = null;
  try { live = JSON.parse(localStorage.getItem(key) || 'null'); } catch {}

  if (!live) {
    // Initialize live state
    live = {
      id: shipment.id,
      lat: shipment.currentLocation.lat,
      lng: shipment.currentLocation.lng,
      speed: randomSpeed(shipment.type),
      heading: calcHeading(
        shipment.currentLocation.lat, shipment.currentLocation.lng,
        shipment.destination.lat, shipment.destination.lng
      ),
      lastUpdate: now,
      distanceCovered: 0,
      totalDistance: haversine(
        shipment.origin.lat, shipment.origin.lng,
        shipment.destination.lat, shipment.destination.lng
      ),
      status: shipment.status,
      events: []
    };
    localStorage.setItem(key, JSON.stringify(live));
  }
  return live;
}

function advanceLivePosition(shipmentId) {
  const ships = getShipments();
  const ship = ships.find(s => s.id === shipmentId);
  if (!ship || ship.status === 'Delivered' || ship.status === 'Order Placed') return;

  const key = 'pes_transport_live_' + shipmentId;
  let live = null;
  try { live = JSON.parse(localStorage.getItem(key) || 'null'); } catch {}
  if (!live) live = getLivePosition(ship);

  const now = Date.now();
  const elapsed = (now - live.lastUpdate) / 1000; // seconds

  // Small random movement toward destination
  const destLat = ship.destination.lat;
  const destLng = ship.destination.lng;
  const dLat = destLat - live.lat;
  const dLng = destLng - live.lng;
  const dist = Math.sqrt(dLat * dLat + dLng * dLng);

  if (dist > 0.005) {
    const step = 0.001 * (0.5 + Math.random() * 0.5); // small step
    const jitter = (Math.random() - 0.5) * 0.0008; // slight wobble
    live.lat += (dLat / dist) * step + jitter;
    live.lng += (dLng / dist) * step + jitter * 0.5;
    live.speed = randomSpeed(ship.type);
    live.heading = calcHeading(live.lat, live.lng, destLat, destLng);
  }

  live.lastUpdate = now;
  live.distanceCovered = haversine(
    ship.origin.lat, ship.origin.lng, live.lat, live.lng
  );

  localStorage.setItem(key, JSON.stringify(live));
  _transportListeners.forEach(fn => { try { fn(shipmentId, live); } catch {} });
}

function startLiveTracking(shipmentId) {
  stopLiveTracking(shipmentId);
  _transportTimers[shipmentId] = setInterval(() => advanceLivePosition(shipmentId), TRANSPORT_TICK_MS);
  advanceLivePosition(shipmentId); // immediate first tick
}

function stopLiveTracking(shipmentId) {
  if (_transportTimers[shipmentId]) {
    clearInterval(_transportTimers[shipmentId]);
    delete _transportTimers[shipmentId];
  }
}

function stopAllTracking() {
  Object.keys(_transportTimers).forEach(stopLiveTracking);
}

function onTransportUpdate(fn) {
  _transportListeners.push(fn);
}

function setManualPosition(shipmentId, lat, lng, city, country) {
  const ships = getShipments();
  const idx = ships.findIndex(s => s.id === shipmentId);
  if (idx === -1) return;

  // Update shipment record
  ships[idx].currentLocation = { lat, lng, city: city || ships[idx].currentLocation.city, country: country || ships[idx].currentLocation.country };
  saveShipments(ships);

  // Update live state
  const key = 'pes_transport_live_' + shipmentId;
  let live = null;
  try { live = JSON.parse(localStorage.getItem(key) || 'null') || {}; } catch { live = {}; }
  live.lat = lat;
  live.lng = lng;
  live.lastUpdate = Date.now();
  localStorage.setItem(key, JSON.stringify(live));
}

// ── MATH HELPERS ────────────────────────────
function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180) * Math.cos(lat2*Math.PI/180) * Math.sin(dLon/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

function calcHeading(lat1, lng1, lat2, lng2) {
  const dLat = lat2 - lat1;
  const dLng = lng2 - lng1;
  let deg = Math.atan2(dLng, dLat) * 180 / Math.PI;
  if (deg < 0) deg += 360;
  return Math.round(deg);
}

function randomSpeed(type) {
  // km/h — road domestic vs air international
  return type === 'international'
    ? 800 + Math.random() * 100
    : 60 + Math.random() * 40;
}

function headingToDirection(deg) {
  const dirs = ['N','NE','E','SE','S','SW','W','NW'];
  return dirs[Math.round(deg / 45) % 8];
}

function getETA(shipment, live) {
  if (!live) return shipment.estimatedDelivery;
  const remaining = haversine(live.lat, live.lng, shipment.destination.lat, shipment.destination.lng);
  const speed = live.speed || randomSpeed(shipment.type);
  const hoursLeft = remaining / speed;
  const eta = new Date(Date.now() + hoursLeft * 3600 * 1000);
  return eta.toISOString().split('T')[0];
}

// ── AUTO STATUS SEQUENCE ─────────────────────
// Automatically advances shipment through all stages
// Order Placed → Processing (2min) → Dispatched (5min) → In Transit (10min)
// → Out for Delivery (varies by distance) → Delivered
// All timers are stored in localStorage so they survive page refreshes

const AUTO_SEQUENCE = [
  'Order Placed',
  'Processing',
  'Dispatched',
  'In Transit',
  'Out for Delivery',
  'Delivered'
];

// Delays between each status step (in milliseconds)
// In production these would be hours/days — for demo purposes use shorter intervals
// Change these values to control speed. Default: realistic simulation
const AUTO_SEQUENCE_DELAYS = {
  'Order Placed':     2  * 60 * 1000,  // 2 min  → Processing
  'Processing':       5  * 60 * 1000,  // 5 min  → Dispatched
  'Dispatched':       10 * 60 * 1000,  // 10 min → In Transit
  'In Transit':       20 * 60 * 1000,  // 20 min → Out for Delivery
  'Out for Delivery': 10 * 60 * 1000,  // 10 min → Delivered
};

function startAutoSequence(shipmentId) {
  const tsKey = 'pes_auto_ts_' + shipmentId;
  const ships  = getShipments();
  const ship   = ships.find(s => s.id === shipmentId);
  if (!ship || ship.status === 'Delivered' || ship.status === 'Returned') return;

  // Record when this step started (if not already recorded)
  const now = Date.now();
  let timestamps = {};
  try { timestamps = JSON.parse(localStorage.getItem(tsKey) || '{}'); } catch {}
  if (!timestamps[ship.status]) {
    timestamps[ship.status] = now;
    localStorage.setItem(tsKey, JSON.stringify(timestamps));
  }

  const curIdx = AUTO_SEQUENCE.indexOf(ship.status);
  if (curIdx < 0 || curIdx >= AUTO_SEQUENCE.length - 1) return;

  const nextStatus = AUTO_SEQUENCE[curIdx + 1];
  const delay      = AUTO_SEQUENCE_DELAYS[ship.status] || (5 * 60 * 1000);
  const elapsed    = now - (timestamps[ship.status] || now);
  const remaining  = Math.max(0, delay - elapsed);

  // Clear any existing timer for this shipment
  if (window._autoSeqTimers && window._autoSeqTimers[shipmentId]) {
    clearTimeout(window._autoSeqTimers[shipmentId]);
  }
  if (!window._autoSeqTimers) window._autoSeqTimers = {};

  window._autoSeqTimers[shipmentId] = setTimeout(() => {
    // Re-read shipments to get latest
    const latest = getShipments();
    const idx = latest.findIndex(s => s.id === shipmentId);
    if (idx === -1 || latest[idx].status !== ship.status) return; // already changed manually

    latest[idx].status = nextStatus;
    latest[idx].statusIndex = AUTO_SEQUENCE.indexOf(nextStatus);
    latest[idx].history = latest[idx].history || [];
    latest[idx].history.push({
      status: nextStatus,
      time: new Date().toLocaleString('en-NG'),
      location: latest[idx].currentLocation.city + ', ' + latest[idx].currentLocation.country,
      note: 'Status automatically updated by tracking system.'
    });

    // If now In Transit or further, start live position tracking
    if (['Dispatched','In Transit','Out for Delivery'].includes(nextStatus)) {
      startLiveTracking(shipmentId);
    }

    saveShipments(latest);

    // Notify any UI listeners
    _transportListeners.forEach(fn => { try { fn(shipmentId, null); } catch {} });

    // Schedule next step
    if (nextStatus !== 'Delivered') {
      startAutoSequence(shipmentId);
    }
  }, remaining);
}

function startAutoSequenceForAll() {
  const ships = getShipments();
  ships.forEach(s => {
    if (s.status !== 'Delivered' && s.status !== 'Returned') {
      startAutoSequence(s.id);
      if (['In Transit','Out for Delivery','Dispatched'].includes(s.status)) {
        startLiveTracking(s.id);
      }
    }
  });
}

// Auto-start when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startAutoSequenceForAll);
} else {
  startAutoSequenceForAll();
}

