/* =============================================
   PARAMOUNT E-STORE — PRODUCTS DATA
   localStorage-backed shared data store
   ============================================= */

const DEFAULT_CATEGORIES = [
  { id: 1,  name: "Accessories",        image: "images/logo.png", description: "Cables, chargers & gadget accessories" },
  { id: 2,  name: "Adult Items",        image: "images/logo.png", description: "Age-restricted products — 18+ only", ageRestricted: true },
  { id: 3,  name: "Air Conditioners",   image: "images/logo.png", description: "Split units, standing & portable ACs" },
  { id: 4,  name: "Baby & Kids",        image: "images/logo.png", description: "Baby gear, toys & nursery items" },
  { id: 5,  name: "Computers & Laptops",image: "images/logo.png", description: "Laptops, desktops & peripherals" },
  { id: 6,  name: "Electronics",        image: "images/logo.png", description: "TVs, audio, cameras & more" },
  { id: 7,  name: "Fans & Cooling",     image: "images/logo.png", description: "Ceiling fans, standing & desk fans" },
  { id: 8,  name: "Furniture & Decor",  image: "images/logo.png", description: "Sofas, beds & home décor" },
  { id: 9,  name: "Generators & Power", image: "images/logo.png", description: "Generators, inverters & solar" },
  { id: 10, name: "Home Appliances",    image: "images/logo.png", description: "Fridges, washing machines & cookers" },
  { id: 11, name: "Kitchen Appliances", image: "images/logo.png", description: "Blenders, microwaves & ovens" },
  { id: 12, name: "Lighting",           image: "images/logo.png", description: "Bulbs, lamps & outdoor lighting" },
  { id: 13, name: "Personal Care",      image: "images/logo.png", description: "Grooming, skincare & health devices" },
  { id: 14, name: "Phones & Tablets",   image: "images/logo.png", description: "Smartphones, tablets & accessories" },
  { id: 15, name: "Security Systems",   image: "images/logo.png", description: "CCTV, alarms & smart locks" },
  { id: 16, name: "Sports & Fitness",   image: "images/logo.png", description: "Exercise equipment & accessories" },
];

const DEFAULT_PRODUCTS = [
  { id:13, name:"1.5HP Inverter Split AC",             category:"Air Conditioners",    price:320000,  image:"images/logo.png", badge:"BESTSELLER", description:"1.5HP inverter split air conditioner with R32 refrigerant, 5-star energy rating, auto-restart, sleep mode, self-cleaning, anti-bacterial filter and 4-way air distribution.",                                                                          stock:"in-stock",  stockQty:24,  featured:true  },
  { id:5,  name:"4-Burner Gas Cooker with Oven",       category:"Home Appliances",    price:185000,  image:"images/logo.png", badge:null,         description:"Stainless steel 4-burner gas cooker with full glass oven, auto-ignition, flame failure device, rotisserie grill and tempered glass lid. 60cm freestanding design.",                                                                                    stock:"in-stock",  stockQty:6,   featured:false },
  { id:1,  name:'55" 4K UHD Smart TV',                 category:"Electronics",        price:420000,  image:"images/logo.png", badge:"BESTSELLER", description:"55-inch 4K Ultra HD Smart TV with HDR10, built-in Wi-Fi, Netflix & YouTube access, 3 HDMI ports and Dolby Audio surround sound. Energy-saving LED backlit display.",                                                                                      stock:"in-stock",  stockQty:16,  featured:true  },
  { id:15, name:"2.5KVA Pure Sine Wave Inverter",      category:"Generators & Power",  price:195000,  image:"images/logo.png", badge:null,         description:"2500VA pure sine wave inverter with 24V input, built-in MPPT solar charge controller, USB charging port, LCD display and battery protection system. Ideal for homes & offices.",                                                                     stock:"in-stock",  stockQty:38,  featured:false },
  { id:14, name:"5KVA Silent Generator",               category:"Generators & Power",  price:620000,  image:"images/logo.png", badge:"PREMIUM",    description:"5KVA soundproof diesel generator with electric start, ATS compatibility, 12-hour run time on full tank, AVR voltage regulation and 4 outlets. Industrial-grade build.",                                                                                 stock:"in-stock",  stockQty:31,  featured:true  },
  { id:18, name:"CCTV 8-Camera Security Kit",          category:"Security Systems",    price:280000,  image:"images/logo.png", badge:"HOT",        description:"Complete 8-camera 5MP CCTV system with 2TB NVR, night vision up to 40m, weatherproof cameras, motion detection alerts, remote viewing via mobile app and 30-day recording.",                                                                          stock:"in-stock",  stockQty:21,  featured:false },
  { id:16, name:"DC Ceiling Fan with LED Light",       category:"Fans & Cooling",      price:85000,   image:"images/logo.png", badge:"NEW",        description:"56-inch DC motor ceiling fan with 18W integrated LED light, remote control, 6-speed settings, silent operation, reversible motor and energy-saving technology.",                                                                                       stock:"in-stock",  stockQty:7,   featured:false },
  { id:4,  name:"Front Load Washing Machine 8kg",      category:"Home Appliances",    price:430000,  image:"images/logo.png", badge:"NEW",        description:"8kg front-loading washing machine with 15 wash programs, quick-wash 30-min cycle, steam clean function, and anti-vibration technology. Quiet and energy efficient.",                                                                                     stock:"in-stock",  stockQty:37,  featured:false },
  { id:9,  name:"HP LaserJet Pro Printer",             category:"Computers & Laptops",price:145000,  image:"images/logo.png", badge:null,         description:"Monochrome laser printer with wireless printing, automatic two-sided printing, 35-page auto document feeder, mobile printing via HP Smart app. Up to 30ppm print speed.",                                                                              stock:"in-stock",  stockQty:34,  featured:false },
  { id:12, name:"High-Speed Blender 2L",               category:"Kitchen Appliances",  price:55000,   image:"images/logo.png", badge:"HOT",        description:"Professional 2-litre blender with 1500W motor, 6-blade stainless steel assembly, 5-speed settings + pulse, BPA-free Tritan jar, and self-cleaning function.",                                                                                        stock:"in-stock",  stockQty:17,  featured:false },
  { id:6,  name:"iPhone 15 Pro Max 256GB",             category:"Phones & Tablets",   price:1150000, image:"images/logo.png", badge:"PREMIUM",    description:"Apple iPhone 15 Pro Max with A17 Pro chip, 48MP triple camera system with 5x optical zoom, titanium design, Action Button, USB-C and up to 29 hours video playback.",                                                                                   stock:"in-stock",  stockQty:13,  featured:true  },
  { id:17, name:"L-Shape Sectional Sofa",              category:"Furniture & Decor",   price:480000,  image:"images/logo.png", badge:null,         description:"Modern L-shaped sectional sofa in premium leatherette upholstery, high-density foam cushions, solid hardwood frame and 6-seater capacity. Available in black and grey.",                                                                                stock:"in-stock",  stockQty:14,  featured:false },
  { id:8,  name:'MacBook Air M2 13" 256GB',            category:"Computers & Laptops",price:1250000, image:"images/logo.png", badge:"BESTSELLER", description:"Apple MacBook Air with M2 chip, 8GB RAM, 256GB SSD, 13.6-inch Liquid Retina display, MagSafe charging, up to 18-hour battery life and fanless silent design.",                                                                                      stock:"in-stock",  stockQty:27,  featured:true  },
  { id:11, name:"Microwave Oven 30L",                  category:"Kitchen Appliances",  price:98000,   image:"images/logo.png", badge:null,         description:"30-litre microwave with grill function, convection cooking, 8 auto-cook menus, child safety lock, LED interior light and stainless steel cavity for easy cleaning.",                                                                                  stock:"in-stock",  stockQty:10,  featured:false },
  { id:7,  name:"Samsung Galaxy Tab S9",               category:"Phones & Tablets",   price:590000,  image:"images/logo.png", badge:null,         description:"11-inch AMOLED display tablet with Snapdragon 8 Gen 2, 128GB storage, IP68 water resistance, S Pen included, DeX mode for desktop experience and 8000mAh battery.",                                                                                   stock:"limited",  stockQty:5,   featured:false },
  { id:3,  name:"Side-by-Side Refrigerator 600L",      category:"Home Appliances",    price:890000,  image:"images/logo.png", badge:"PREMIUM",    description:"600-litre side-by-side refrigerator with water & ice dispenser, multi-flow cooling, inverter compressor, frost-free technology and LED interior lighting. A+ energy rating.",                                                                           stock:"in-stock",  stockQty:30,  featured:true  },
  { id:10, name:"Stand Mixer 6.5L Professional",       category:"Kitchen Appliances",  price:215000,  image:"images/logo.png", badge:"NEW",        description:"6.5-litre professional stand mixer with 10-speed settings, stainless steel bowl, dough hook, flat beater and wire whip attachments. 800W powerful motor with planetary mixing action.",                                                                stock:"in-stock",  stockQty:41,  featured:false },
  { id:2,  name:"Wireless Bluetooth Speaker",          category:"Electronics",        price:38500,   image:"images/logo.png", badge:"HOT",        description:"360° surround sound portable speaker with 24-hour battery life, IPX7 waterproof rating, dual pairing mode and deep bass. Perfect for indoor and outdoor use.",                                                                                              stock:"in-stock",  stockQty:23,  featured:false },
];

const DEFAULT_ORDERS = [];

function getProducts() {
  try {
    var stored = localStorage.getItem('pes_products');
    if (!stored) {
      localStorage.setItem('pes_products', JSON.stringify(DEFAULT_PRODUCTS));
      return DEFAULT_PRODUCTS;
    }
    var parsed = JSON.parse(stored);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      localStorage.setItem('pes_products', JSON.stringify(DEFAULT_PRODUCTS));
      return DEFAULT_PRODUCTS;
    }
    // Ensure every product has an images array (migration guard)
    parsed = parsed.map(function(p) {
      if (!p.images || !Array.isArray(p.images) || p.images.length === 0) {
        p.images = p.image ? [p.image] : ['images/logo.png'];
      }
      if (!p.image) p.image = p.images[0];
      return p;
    });
    return parsed;
  } catch(e) {
    return DEFAULT_PRODUCTS;
  }
}
function saveProducts(products) { localStorage.setItem('pes_products', JSON.stringify(products)); }

function getCategories() {
  try {
    const stored = localStorage.getItem('pes_categories');
    if (!stored) {
      localStorage.setItem('pes_categories', JSON.stringify(DEFAULT_CATEGORIES));
      return DEFAULT_CATEGORIES;
    }
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      localStorage.setItem('pes_categories', JSON.stringify(DEFAULT_CATEGORIES));
      return DEFAULT_CATEGORIES;
    }
    return parsed;
  } catch(e) {
    return DEFAULT_CATEGORIES;
  }
}
function saveCategories(cats) { localStorage.setItem('pes_categories', JSON.stringify(cats)); }

function getOrders() {
  const stored = localStorage.getItem('pes_orders');
  if (!stored) return DEFAULT_ORDERS;
  return JSON.parse(stored);
}
function saveOrders(orders) { localStorage.setItem('pes_orders', JSON.stringify(orders)); }
function addOrder(order) { const orders = getOrders(); orders.unshift(order); saveOrders(orders); }

function formatPrice(n) {
  return '₦' + Number(n).toLocaleString('en-NG', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function getProductSerial(p) {
  // Use stored serial if present, otherwise generate from ID
  if (p.serial) return p.serial;
  const num = String(p.id).padStart(5, '0');
  return 'PES-' + num;
}
function generateId() { return Date.now() + Math.floor(Math.random() * 1000); }
function showToast(msg) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2800);
}

/* =============================================
   BULK ORDER DISCOUNT TIERS
   ============================================= */
const DEFAULT_BULK_TIERS = [
  { minQty: 5,   maxQty: 9,   discount: 5,  label: "Starter" },
  { minQty: 10,  maxQty: 24,  discount: 10, label: "Silver" },
  { minQty: 25,  maxQty: 49,  discount: 15, label: "Gold" },
  { minQty: 50,  maxQty: 99,  discount: 20, label: "Platinum" },
  { minQty: 100, maxQty: null,discount: 28, label: "Enterprise" },
];

function getBulkTiers() {
  const s = localStorage.getItem('pes_bulk_tiers');
  if (!s) { localStorage.setItem('pes_bulk_tiers', JSON.stringify(DEFAULT_BULK_TIERS)); return DEFAULT_BULK_TIERS; }
  return JSON.parse(s);
}

/* =============================================
   SHIPMENT / TRACKING DATA
   ============================================= */
const SHIPMENT_STATUSES = ['Order Placed','Processing','Dispatched','In Transit','Out for Delivery','Delivered','Returned'];

const DEFAULT_SHIPMENTS = [
  {
    id: 'PES-TRK-001',
    orderId: 'PES-DEMO-001',
    customer: 'Adebayo Okonkwo',
    email: 'adebayo@example.com',
    phone: '+234 801 234 5678',
    product: '55" 4K UHD Smart TV × 1',
    origin: { city: 'Uyo', country: 'Nigeria', lat: 5.0377, lng: 7.9128 },
    destination: { city: 'Abuja', country: 'Nigeria', lat: 9.0579, lng: 7.4951 },
    currentLocation: { city: 'Port Harcourt', country: 'Nigeria', lat: 4.8156, lng: 7.0498 },
    status: 'In Transit',
    statusIndex: 3,
    carrier: 'Paramount Logistics',
    estimatedDelivery: '2025-12-18',
    dispatchDate: '2025-12-14',
    type: 'domestic',
    weight: '22kg',
    value: 420000,
    history: [
      { status: 'Order Placed',  time: '2025-12-13 09:15', location: 'Uyo, Akwa Ibom',    note: 'Order confirmed and payment received.' },
      { status: 'Processing',    time: '2025-12-13 14:30', location: 'Uyo Warehouse',      note: 'Item picked, packed and labelled.' },
      { status: 'Dispatched',    time: '2025-12-14 07:00', location: 'Uyo Hub',            note: 'Handed to carrier for dispatch.' },
      { status: 'In Transit',    time: '2025-12-14 18:45', location: 'Port Harcourt',      note: 'En route to FCT Abuja.' },
    ]
  },
  {
    id: 'PES-TRK-002',
    orderId: 'PES-DEMO-002',
    customer: 'Chidi Eze',
    email: 'chidi@example.com',
    phone: '+234 802 345 6789',
    product: 'MacBook Air M2 × 2',
    origin: { city: 'Uyo', country: 'Nigeria', lat: 5.0377, lng: 7.9128 },
    destination: { city: 'Accra', country: 'Ghana', lat: 5.6037, lng: -0.1870 },
    currentLocation: { city: 'Accra Port', country: 'Ghana', lat: 5.5502, lng: -0.2174 },
    status: 'Out for Delivery',
    statusIndex: 4,
    carrier: 'DHL Express',
    estimatedDelivery: '2025-12-17',
    dispatchDate: '2025-12-12',
    type: 'international',
    weight: '5.8kg',
    value: 2500000,
    history: [
      { status: 'Order Placed',      time: '2025-12-10 11:00', location: 'Online',                note: 'Bulk order confirmed.' },
      { status: 'Processing',        time: '2025-12-11 09:00', location: 'Uyo Warehouse',         note: 'Customs documents prepared.' },
      { status: 'Dispatched',        time: '2025-12-12 06:30', location: 'Uyo Export Hub',        note: 'Cleared for international export.' },
      { status: 'In Transit',        time: '2025-12-12 14:00', location: 'Kotoka Airport, GH',    note: 'Arrived Accra, customs clearance.' },
      { status: 'Out for Delivery',  time: '2025-12-16 08:00', location: 'Accra Port, GH',        note: 'With delivery agent.' },
    ]
  },
  {
    id: 'PES-TRK-003',
    orderId: 'PES-DEMO-003',
    customer: 'Fatima Al-Hassan',
    email: 'fatima@example.com',
    phone: '+234 803 456 7890',
    product: '5KVA Silent Generator × 3',
    origin: { city: 'Uyo', country: 'Nigeria', lat: 5.0377, lng: 7.9128 },
    destination: { city: 'Kano', country: 'Nigeria', lat: 12.0022, lng: 8.5920 },
    currentLocation: { city: 'Kaduna', country: 'Nigeria', lat: 10.5105, lng: 7.4165 },
    status: 'In Transit',
    statusIndex: 3,
    carrier: 'GIG Logistics',
    estimatedDelivery: '2025-12-19',
    dispatchDate: '2025-12-15',
    type: 'domestic',
    weight: '210kg',
    value: 1860000,
    history: [
      { status: 'Order Placed', time: '2025-12-14 10:00', location: 'Online',              note: 'Bulk order – 3 units.' },
      { status: 'Processing',   time: '2025-12-14 16:00', location: 'Uyo Warehouse',       note: 'Units tested and crated.' },
      { status: 'Dispatched',   time: '2025-12-15 06:00', location: 'Uyo Depot',           note: 'Truck departed Uyo.' },
      { status: 'In Transit',   time: '2025-12-16 20:00', location: 'Kaduna State',        note: 'Overnight transit to Kano.' },
    ]
  },
];

function getShipments() {
  const s = localStorage.getItem('pes_shipments');
  if (!s) { localStorage.setItem('pes_shipments', JSON.stringify(DEFAULT_SHIPMENTS)); return DEFAULT_SHIPMENTS; }
  return JSON.parse(s);
}
function saveShipments(sh) { localStorage.setItem('pes_shipments', JSON.stringify(sh)); }

function addShipment(sh) {
  const all = getShipments(); all.unshift(sh); saveShipments(all);
}


