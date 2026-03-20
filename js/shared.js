/* =============================================
   PARAMOUNT E-STORE — SHARED UTILITIES v9
   Footer injection, Policy popups, Google Sheets
   ============================================= */

// ── SHARED FOOTER HTML ─────────────────────────────
const SHARED_FOOTER_HTML = `
<footer class="footer" id="footer-main">
  <div class="footer-inner">
  <div class="footer-top">
    <div class="footer-brand">
      <span class="footer-logo">PARAMOUNT</span>
      <span class="footer-tagline">E — Mart</span>
      <p class="footer-text">Your trusted destination for premium home appliances, electronics, and everything that powers modern living in Nigeria.</p>
      <div class="social-links">
        <a href="https://instagram.com/ParamountEMart" data-social="instagram" target="_blank" class="social-btn" title="Instagram"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="20" height="20" rx="5"/><circle cx="12" cy="12" r="5"/><circle cx="17.5" cy="6.5" r="1" fill="currentColor" stroke="none"/></svg></a>
        <a href="https://facebook.com/ParamountEMart" data-social="facebook" target="_blank" class="social-btn" title="Facebook"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"/></svg></a>
        <a href="https://twitter.com/ParamountEMart" data-social="twitter" target="_blank" class="social-btn" title="X / Twitter"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg></a>
        <a href="https://tiktok.com/@ParamountEMart" data-social="tiktok" target="_blank" class="social-btn" title="TikTok"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-2.88 2.5 2.89 2.89 0 01-2.89-2.89 2.89 2.89 0 012.89-2.89c.28 0 .54.04.79.1V9.01a6.33 6.33 0 00-.79-.05 6.34 6.34 0 00-6.34 6.34 6.34 6.34 0 006.34 6.34 6.34 6.34 0 006.33-6.34V8.69a8.18 8.18 0 004.78 1.52V6.74a4.85 4.85 0 01-1.01-.05z"/></svg></a>
        <a href="https://wa.me/2349160439848" data-social="whatsapp" target="_blank" class="social-btn" title="WhatsApp"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg></a>
        <a href="https://youtube.com/@ParamountEMart" data-social="youtube" target="_blank" class="social-btn" title="YouTube"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22.54 6.42a2.78 2.78 0 00-1.95-1.97C18.88 4 12 4 12 4s-6.88 0-8.59.46A2.78 2.78 0 001.46 6.42 29 29 0 001 12a29 29 0 00.46 5.58A2.78 2.78 0 003.41 19.6C5.12 20 12 20 12 20s6.88 0 8.59-.46a2.78 2.78 0 001.95-1.95A29 29 0 0023 12a29 29 0 00-.46-5.58z"/><polygon points="9.75 15.02 15.5 12 9.75 8.98 9.75 15.02" fill="currentColor" stroke="none"/></svg></a>
      </div>
    </div>
    <div class="footer-col">
      <h4>Shop</h4>
      <a href="index.html" onclick="pesFooterNav('shop:Electronics')">Electronics</a>
      <a href="index.html" onclick="pesFooterNav('shop:Home Appliances')">Home Appliances</a>
      <a href="index.html" onclick="pesFooterNav('shop:Phones & Tablets')">Phones & Tablets</a>
      <a href="index.html" onclick="pesFooterNav('shop:Computers & Laptops')">Computers & Laptops</a>
      <a href="index.html" onclick="pesFooterNav('shop:Kitchen Appliances')">Kitchen Appliances</a>
      <a href="index.html" onclick="pesFooterNav('shop:Air Conditioners')">Air Conditioners</a>
      <a href="index.html" onclick="pesFooterNav('shop:Generators & Power')">Generators & Power</a>
    </div>
    <div class="footer-col">
      <h4>Quick Links</h4>
      <a href="index.html">Main Store</a>
      <a href="tracking.html">Track Your Order</a>
      <a href="support.html">Support / Help Desk</a>
      <a href="#" onclick="openPrivacyPolicy();return false;">Privacy Policy</a>
      <a href="#" onclick="openTermsConditions();return false;">Terms &amp; Conditions</a>
      <a href="#" onclick="openRefundPolicy();return false;">Refund Policy</a>
      <a href="index.html" onclick="pesFooterNav('contact')">Contact Us</a>
    </div>
    <div class="footer-col">
      <h4>Contact Us</h4>
      <p class="footer-contact-item"><span class="footer-contact-icon">✉</span><a href="mailto:paramountdigitalservices@gmail.com">paramountdigitalservices@gmail.com</a></p>
      <p class="footer-contact-item"><span class="footer-contact-icon">📞</span><a href="tel:+2349160439848">+234 916 043 9848</a></p>
      <p class="footer-contact-item"><span class="footer-contact-icon">🕐</span>Mon – Sat: 8am – 6pm</p>
      <p class="footer-contact-item"><span class="footer-contact-icon">📍</span>Uyo, Akwa Ibom State, Nigeria</p>
      <div class="footer-payment-badge"><span>🔒 Secured by</span><strong>Flutterwave</strong></div>
    </div>
  </div>

  <!-- NEWSLETTER STRIP ─────────────────────────────── -->
  <div class="footer-newsletter-strip">
    <div class="footer-newsletter-inner">
      <div class="fns-text">
        <div class="fns-heading">Stay in the Loop</div>
        <div class="fns-sub">Deals, new arrivals, and exclusive offers — straight to your inbox.</div>
      </div>
      <form class="pes-newsletter-form fns-form" onsubmit="return false;">
        <div class="fns-fields">
          <input type="text"  name="firstName" placeholder="First name" class="fns-input" autocomplete="given-name"/>
          <input type="email" name="email"     placeholder="Email address" class="fns-input" required autocomplete="email"/>
          <button type="submit" class="fns-btn">Subscribe →</button>
        </div>
        <label class="fns-consent">
          <input type="checkbox" name="consent" required/>
          <span>I agree to receive emails from Paramount E-mart. Unsubscribe anytime.</span>
        </label>
        <div class="pes-form-msg" style="display:none;margin-top:8px;"></div>
      </form>
    </div>
  </div>

  </div><!-- /.footer-inner -->

  <!-- SATELLITE MAP STRIP — full width, outside footer-inner -->
  <div class="footer-map-section">
    <div class="footer-map-header">
      <span class="footer-map-eyebrow">Paramount E-mart · Uyo, Akwa Ibom · Nigeria</span>
      <span class="footer-map-label">We Deliver Worldwide</span>
    </div>
    <div class="footer-map-wrap">
      <div id="satMapWrap" class="sat-map-container"></div>
      <div class="footer-map-overlay-info">
        <div class="fmi-item"><span class="fmi-dot fmi-dot-green"></span>Nationwide Delivery — All 36 States</div>
        <div class="fmi-item"><span class="fmi-dot fmi-dot-blue"></span>West Africa Export — Ghana, Benin, Côte d'Ivoire</div>
        <div class="fmi-item"><span class="fmi-dot fmi-dot-white"></span>International Shipping — On Request</div>
      </div>
    </div>
  </div>

  <div class="footer-inner">
  <div class="footer-bottom">
    <span>© 2025 Paramount E-mart. All rights reserved.</span>
    <span class="footer-bottom-links">
      <a href="#" onclick="openPrivacyPolicy();return false;">Privacy Policy</a><span>·</span>
      <a href="#" onclick="openTermsConditions();return false;">Terms of Service</a><span>·</span>
      <a href="#" onclick="openRefundPolicy();return false;">Refund Policy</a>
    </span>
    <span class="admin-secret-trigger" onclick="window.location.href='pds-control-panel.html'" title="">△</span>
  </div>
  </div><!-- /.footer-bottom -->
  </div><!-- /.footer-inner -->
</footer>

<style>
/* ── FOOTER SATELLITE MAP ── */
.footer-map-section{border-top:1px solid #1a1a1a;}
.footer-map-header{display:flex;align-items:center;justify-content:space-between;padding:18px 48px;border-bottom:1px solid #161616;max-width:1400px;margin:0 auto;box-sizing:border-box;}
.footer-map-eyebrow{font-size:10px;letter-spacing:0.35em;text-transform:uppercase;color:#444;font-weight:600;}
.footer-map-label{font-size:10px;letter-spacing:0.25em;text-transform:uppercase;color:#333;}
.footer-map-wrap{position:relative;height:260px;overflow:hidden;}
.sat-map-container{width:100%;height:100%;background:#000;}
.footer-map-overlay-info{position:absolute;bottom:14px;right:18px;display:flex;flex-direction:column;gap:7px;background:rgba(8,8,8,0.88);border:1px solid #1e1e1e;padding:12px 16px;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);}
.fmi-item{display:flex;align-items:center;gap:8px;font-size:10px;color:#888;letter-spacing:0.04em;white-space:nowrap;}
.fmi-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
.fmi-dot-green{background:#4caf50;box-shadow:0 0 6px #4caf50;}
.fmi-dot-blue{background:#42a5f5;box-shadow:0 0 6px #42a5f5;}
.fmi-dot-white{background:#fff;box-shadow:0 0 6px rgba(255,255,255,0.5);}
@media(max-width:600px){
  .footer-map-wrap{height:190px;}
  .footer-map-overlay-info{right:8px;bottom:8px;padding:8px 12px;}
  .fmi-item{font-size:9px;}
  .footer-map-header{padding:14px 16px;flex-direction:column;gap:4px;align-items:flex-start;}
}
@keyframes globePulse{0%,100%{box-shadow:inset -28px -28px 56px rgba(0,0,0,.7),inset 10px 10px 36px rgba(255,255,255,.06),0 0 72px rgba(21,101,192,.25),0 0 140px rgba(21,101,192,.08);}50%{box-shadow:inset -28px -28px 56px rgba(0,0,0,.7),inset 10px 10px 36px rgba(255,255,255,.06),0 0 100px rgba(21,101,192,.4),0 0 200px rgba(21,101,192,.15);}}
</style>

<!-- ─── PRIVACY POLICY POPUP ─────────────────── -->
<div class="policy-overlay" id="privacyOverlay" onclick="closePrivacyPolicy()"></div>
<div class="policy-popup" id="privacyPopup">
  <div class="policy-popup-head">
    <div>
      <div class="policy-popup-eyebrow">Legal Document</div>
      <h2 class="policy-popup-title">Privacy Policy</h2>
    </div>
    <button class="policy-popup-close" onclick="closePrivacyPolicy()">✕</button>
  </div>
  <div class="policy-popup-body">
    <p class="policy-effective">Effective Date: 1 January 2025 &nbsp;·&nbsp; Last Updated: 1 January 2025</p>
    <div class="policy-content">
      <h3>1. Introduction</h3>
      <p>Paramount E-mart ("we", "our", or "us") is committed to protecting your personal information and your right to privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you visit our website or make a purchase with us.</p>

      <h3>2. Information We Collect</h3>
      <p>We collect information you provide directly when you:</p>
      <ul>
        <li>Place an order (name, email, phone, delivery address)</li>
        <li>Subscribe to our newsletter or promotional emails</li>
        <li>Contact our customer service team</li>
      </ul>
      <p>We also automatically collect certain technical data including your IP address, browser type, pages visited, and time spent on our site to help us improve our services.</p>

      <h3>3. How We Use Your Information</h3>
      <p>We use your personal information to:</p>
      <ul>
        <li>Process and fulfil your orders</li>
        <li>Send order confirmations and shipment tracking updates</li>
        <li>Communicate with you about your orders, returns, and enquiries</li>
        <li>Send promotional emails and offers (with your consent)</li>
        <li>Improve our website, products, and services</li>
        <li>Comply with legal obligations</li>
      </ul>

      <h3>4. Sharing Your Information</h3>
      <p>We do not sell, trade, or rent your personal information to third parties. We may share your information with trusted service providers who assist us in operating our website or conducting our business, including:</p>
      <ul>
        <li><strong>Flutterwave</strong> – for secure card & mobile money processing</li>
        <li><strong>Logistics partners</strong> – for order delivery</li>
        <li><strong>Google</strong> – for analytics and email marketing (with consent)</li>
      </ul>

      <h3>5. Cookies</h3>
      <p>We use cookies and similar technologies to enhance your browsing experience, remember your preferences, and analyse site traffic. You can disable cookies in your browser settings, though some features may not function correctly.</p>

      <h3>6. Data Security</h3>
      <p>We implement industry-standard security measures including SSL encryption, secure payment processing through Flutterwave, and restricted access to your personal data. However, no method of internet transmission is 100% secure.</p>

      <h3>7. Data Retention</h3>
      <p>We retain your personal data for as long as necessary to fulfil the purposes outlined in this policy, comply with legal obligations, resolve disputes, and enforce our agreements.</p>

      <h3>8. Your Rights</h3>
      <p>You have the right to:</p>
      <ul>
        <li>Access the personal data we hold about you</li>
        <li>Request correction of inaccurate data</li>
        <li>Request deletion of your data</li>
        <li>Opt out of marketing communications at any time</li>
        <li>Lodge a complaint with the relevant data protection authority</li>
      </ul>

      <h3>9. Third-Party Links</h3>
      <p>Our website may contain links to third-party websites. We are not responsible for the privacy practices of those sites and encourage you to review their privacy policies.</p>

      <h3>10. Children's Privacy</h3>
      <p>Our services are not directed to individuals under the age of 18. We do not knowingly collect personal information from children.</p>

      <h3>11. Changes to This Policy</h3>
      <p>We may update this Privacy Policy from time to time. We will notify you of significant changes by updating the date at the top of this page. Continued use of our services after changes constitutes acceptance of the updated policy.</p>

      <h3>12. Contact Us</h3>
      <p>If you have questions about this Privacy Policy or our data practices, please contact us at:<br/>
      <strong>Email:</strong> privacy@paramountemart.com<br/>
      <strong>Phone:</strong> +234 916 043 9848<br/>
      <strong>Address:</strong> Uyo, Akwa Ibom State, Nigeria</p>
    </div>
  </div>
  <div class="policy-popup-foot">
    <button class="policy-accept-btn" onclick="closePrivacyPolicy()">I Understand</button>
  </div>
</div>

<!-- ─── TERMS & CONDITIONS POPUP ──────────────── -->
<div class="policy-overlay" id="termsOverlay" onclick="closeTermsConditions()"></div>
<div class="policy-popup" id="termsPopup">
  <div class="policy-popup-head">
    <div>
      <div class="policy-popup-eyebrow">Legal Document</div>
      <h2 class="policy-popup-title">Terms & Conditions</h2>
    </div>
    <button class="policy-popup-close" onclick="closeTermsConditions()">✕</button>
  </div>
  <div class="policy-popup-body">
    <p class="policy-effective">Effective Date: 1 January 2025 &nbsp;·&nbsp; Last Updated: 1 January 2025</p>
    <div class="policy-content">
      <h3>1. Acceptance of Terms</h3>
      <p>By accessing or using the Paramount E-mart website and services, you agree to be bound by these Terms and Conditions. If you do not agree, please do not use our services.</p>

      <h3>2. Use of the Website</h3>
      <p>You agree to use this website only for lawful purposes. You must not:</p>
      <ul>
        <li>Provide false or misleading information during purchase or registration</li>
        <li>Attempt to gain unauthorised access to any part of the website</li>
        <li>Use automated tools to scrape or copy content from the website</li>
        <li>Engage in any conduct that disrupts or harms the website's functionality</li>
      </ul>

      <h3>3. Products and Pricing</h3>
      <p>All prices are displayed in Nigerian Naira (₦). We reserve the right to modify prices at any time without prior notice. Product descriptions and images are provided for informational purposes and may vary slightly from the actual product.</p>

      <h3>4. Orders and Payment</h3>
      <p>By placing an order, you confirm that all information provided is accurate and complete. Payment is processed securely via Flutterwave, OPay, or Crypto. Orders are confirmed only after successful payment processing.</p>

      <h3>5. Delivery</h3>
      <p>We deliver nationwide across Nigeria. Delivery timelines are estimates and may be affected by location, logistics partner availability, and unforeseen circumstances. We are not liable for delays caused by third-party logistics providers.</p>

      <h3>6. Cancellations</h3>
      <p>Orders may be cancelled within 2 hours of placement if they have not yet been dispatched. Contact us immediately at info@paramountemart.com or +234 916 043 9848. Once dispatched, cancellation is not possible but a return may be initiated.</p>

      <h3>8. Returns and Refunds</h3>
      <p>We accept returns of unused products in original packaging within 7 days of delivery. To initiate a return, contact our support team with your order reference. Refunds are processed within 5–10 business days after we receive and inspect the returned item.</p>

      <h3>9. Warranty</h3>
      <p>All products sold by Paramount E-mart carry the manufacturer's warranty. Paramount offers an additional 30-day quality guarantee on all items. Warranty claims must be supported by the original receipt or order reference.</p>

      <h3>10. Intellectual Property</h3>
      <p>All content on this website including text, images, logos, and design elements are the intellectual property of Paramount E-mart or its licensors. Reproduction without written consent is strictly prohibited.</p>

      <h3>11. Limitation of Liability</h3>
      <p>To the fullest extent permitted by law, Paramount E-mart shall not be liable for any indirect, incidental, or consequential damages arising from the use of our products or services. Our liability shall not exceed the value of the order in question.</p>

      <h3>12. Governing Law</h3>
      <p>These Terms and Conditions are governed by the laws of the Federal Republic of Nigeria. Any disputes shall be subject to the exclusive jurisdiction of Nigerian courts.</p>

      <h3>13. Changes to Terms</h3>
      <p>We reserve the right to modify these Terms at any time. Continued use of the website after changes constitutes your acceptance of the new Terms.</p>

      <h3>14. Contact</h3>
      <p>For any questions regarding these Terms, please contact:<br/>
      <strong>Email:</strong> legal@paramountemart.com<br/>
      <strong>Phone:</strong> +234 916 043 9848</p>
    </div>
  </div>
  <div class="policy-popup-foot">
    <button class="policy-accept-btn" onclick="closeTermsConditions()">I Accept</button>
  </div>
</div>

<!-- ─── REFUND POLICY POPUP ───────────────────── -->
<div class="policy-overlay" id="refundOverlay" onclick="closeRefundPolicy()"></div>
<div class="policy-popup" id="refundPopup">
  <div class="policy-popup-head">
    <div>
      <div class="policy-popup-eyebrow">Legal Document</div>
      <h2 class="policy-popup-title">Refund Policy</h2>
    </div>
    <button class="policy-popup-close" onclick="closeRefundPolicy()">✕</button>
  </div>
  <div class="policy-popup-body">
    <p class="policy-effective">Effective Date: 1 January 2025</p>
    <div class="policy-content">
      <h3>Our Commitment</h3>
      <p>At Paramount E-mart, your satisfaction is our priority. If you are not completely happy with your purchase, we are here to help.</p>

      <h3>Return Eligibility</h3>
      <ul>
        <li>Items must be returned within <strong>7 days</strong> of delivery</li>
        <li>Products must be unused and in original packaging with all accessories</li>
        <li>Proof of purchase (order ID or receipt) is required</li>
        <li>Items must not be damaged due to misuse or negligence</li>
      </ul>

      <h3>Non-Returnable Items</h3>
      <ul>
        <li>Items marked as "Final Sale" or clearance</li>
        <li>Products with broken seals or evidence of use</li>
        <li>Software, digital downloads, or consumable goods</li>
        <li>Custom or specially ordered items</li>
      </ul>

      <h3>Refund Process</h3>
      <p>Once we receive and inspect the returned item, we will notify you of the approval or rejection of your refund. Approved refunds are processed within <strong>5–10 business days</strong> back to your original payment method via Paystack.</p>

      <h3>Exchanges</h3>
      <p>We replace items only if they are defective or damaged upon receipt. If you need an exchange, contact us at returns@paramountemart.com within 48 hours of delivery with photographic evidence.</p>

      <h3>Shipping Costs</h3>
      <p>Return shipping costs are the customer's responsibility unless the return is due to our error (wrong item, defective product). We recommend using a trackable shipping service.</p>

      <h3>Contact for Returns</h3>
      <p><strong>Email:</strong> returns@paramountemart.com<br/>
      <strong>Phone:</strong> +234 916 043 9848<br/>
      <strong>Hours:</strong> Monday – Saturday, 8am – 6pm</p>
    </div>
  </div>
  <div class="policy-popup-foot">
    <button class="policy-accept-btn" onclick="closeRefundPolicy()">Close</button>
  </div>
</div>
`;











// ── INJECT FOOTER IF NOT ALREADY PRESENT ──────────
function injectSharedFooter() {
  const existing = document.getElementById('footer-main');
  if (existing) return; // Already in DOM (index.html has it inline)
  const div = document.createElement('div');
  div.innerHTML = SHARED_FOOTER_HTML;
  while (div.firstChild) document.body.appendChild(div.firstChild);
}



// ── SATELLITE MAP (footer) ─────────────────────────
function initSharedSatMap() {
  var wrap = document.getElementById('satMapWrap');
  if (!wrap || wrap.dataset.init) return;
  wrap.dataset.init = '1';
  // Google Maps Embed satellite — set MAPS_KEY in .env or via Admin → Integrations
  var KEY = '';  // set your Maps Embed API key here
  if (KEY && KEY.length > 10) {
    var iframe = document.createElement('iframe');
    iframe.setAttribute('loading','lazy');
    iframe.setAttribute('referrerpolicy','no-referrer-when-downgrade');
    iframe.setAttribute('allowfullscreen','');
    iframe.style.cssText = 'width:100%;height:100%;border:0;display:block;';
    iframe.src = 'https://www.google.com/maps/embed/v1/view?key='+KEY+'&center=5.0377,7.9128&zoom=4&maptype=satellite';
    wrap.appendChild(iframe);
  } else {
    _renderFooterGlobe(wrap);
  }
}

function _renderFooterGlobe(wrap) {
  wrap.innerHTML =
    '<div style="width:100%;height:100%;position:relative;overflow:hidden;background:#000;">' +
      '<canvas id="footerStarCanvas" style="position:absolute;inset:0;width:100%;height:100%;"></canvas>' +
      '<div style="position:absolute;width:min(240px,55%);height:min(240px,55%);top:50%;left:50%;transform:translate(-50%,-50%);border-radius:50%;' +
        'background:radial-gradient(circle at 35% 35%,#1a6b3c 0%,#0e4a28 14%,#0a3219 24%,#1565c0 30%,#0d47a1 42%,#083378 52%,#0a3219 57%,#1a6b3c 65%,#1565c0 76%,#083378 87%,#000428 100%);' +
        'box-shadow:inset -24px -24px 48px rgba(0,0,0,.7),inset 8px 8px 32px rgba(255,255,255,.06),0 0 64px rgba(21,101,192,.25);' +
        'animation:globePulse 6s ease-in-out infinite;"></div>' +
      '<div style="position:absolute;width:min(240px,55%);height:min(240px,55%);top:50%;left:50%;transform:translate(-50%,-50%);border-radius:50%;' +
        'background:radial-gradient(circle at 28% 28%,rgba(255,255,255,.13) 0%,rgba(255,255,255,.04) 38%,transparent 68%);pointer-events:none;"></div>' +
      '<div style="position:absolute;bottom:12px;left:0;right:0;text-align:center;font-family:Montserrat,sans-serif;font-size:10px;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.25);">Uyo · Akwa Ibom · Nigeria</div>' +
    '</div>';
  var canvas = document.getElementById('footerStarCanvas');
  if (!canvas) return;
  requestAnimationFrame(function() {
    canvas.width  = canvas.offsetWidth  || 800;
    canvas.height = canvas.offsetHeight || 260;
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#000';
    ctx.fillRect(0,0,canvas.width,canvas.height);
    for (var i=0;i<280;i++) {
      ctx.beginPath();
      ctx.arc(Math.random()*canvas.width, Math.random()*canvas.height, Math.random()*1.3, 0, Math.PI*2);
      ctx.fillStyle = 'rgba(255,255,255,'+(Math.random()*.85+.1)+')';
      ctx.fill();
    }
  });
}

// ── POLICY POPUP FUNCTIONS ────────────────────────
function openPrivacyPolicy()  { document.getElementById('privacyOverlay').classList.add('open'); document.getElementById('privacyPopup').classList.add('open'); document.body.style.overflow='hidden'; }
function closePrivacyPolicy() { document.getElementById('privacyOverlay').classList.remove('open'); document.getElementById('privacyPopup').classList.remove('open'); document.body.style.overflow=''; }
function openTermsConditions()  { document.getElementById('termsOverlay').classList.add('open'); document.getElementById('termsPopup').classList.add('open'); document.body.style.overflow='hidden'; }
function closeTermsConditions() { document.getElementById('termsOverlay').classList.remove('open'); document.getElementById('termsPopup').classList.remove('open'); document.body.style.overflow=''; }
function openRefundPolicy()  { document.getElementById('refundOverlay').classList.add('open'); document.getElementById('refundPopup').classList.add('open'); document.body.style.overflow='hidden'; }
function closeRefundPolicy() { document.getElementById('refundOverlay').classList.remove('open'); document.getElementById('refundPopup').classList.remove('open'); document.body.style.overflow=''; }

// ── GOOGLE SHEETS INTEGRATION ─────────────────────
// Replace GOOGLE_SCRIPT_URL with your deployed Google Apps Script Web App URL
// See setup instructions in admin panel → Integrations tab
const GOOGLE_SCRIPT_URL = localStorage.getItem('pes_gsheet_url') || '';

async function submitToGoogleSheets(sheetName, data) {
  const url = localStorage.getItem('pes_gsheet_url') || GOOGLE_SCRIPT_URL;
  if (!url) { console.warn('Google Sheets URL not configured'); return false; }
  try {
    await fetch(url, {
      method: 'POST',
      mode: 'no-cors',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sheet: sheetName, data, timestamp: new Date().toISOString() })
    });
    return true;
  } catch(e) { console.error('Google Sheets submit error:', e); return false; }
}

// Save customer data to Google Sheets on checkout
async function saveCustomerToSheets(customer) {
  return submitToGoogleSheets('Customers', {
    name: customer.name,
    email: customer.email,
    phone: customer.phone,
    address: customer.address,
    source: customer.source || 'Store'
  });
}

// Save order data to Google Sheets
async function saveOrderToSheets(order) {
  return submitToGoogleSheets('Orders', order);
}


// ── FOOTER NAV — cross-page popup opener ─────────────────
function pesFooterNav(action) {
  if (action.startsWith('shop:')) {
    const cat = action.slice(5);
    if (window.openShopPopupFiltered) {
      // Already on index — open directly
      openShopPopupFiltered(cat);
      return;
    }
    // On another page — navigate and open
    sessionStorage.setItem('pes_open', 'shop:' + cat);
    window.location = 'index.html';
    return;
  }
  if (action === 'contact') {
    if (window.openContactPopup) { openContactPopup(); return; }
    sessionStorage.setItem('pes_open', 'contact');
    window.location = 'index.html';
    return;
  }
  if (action === 'featured') {
    if (window.openFeaturedPopup) { openFeaturedPopup(); return; }
    sessionStorage.setItem('pes_open', 'featured');
    window.location = 'index.html';
    return;
  }
}

// ══════════════════════════════════════════════════════
//  PES DIALOG SYSTEM
//  Replaces all browser confirm() / alert() calls
//  pesConfirm(msg, onYes, onNo, opts)
//  pesAlert(msg, onOk, opts)
//  pesSuccess(title, detail, onOk)
//  pesDanger(msg, confirmLabel, onYes, onNo)
// ══════════════════════════════════════════════════════
(function() {
  // Inject HTML once
  function injectDialogHtml() {
    if (document.getElementById('pesDialogOverlay')) return;
    const div = document.createElement('div');
    div.innerHTML = `
      <div class="pes-dialog-overlay" id="pesDialogOverlay"></div>
      <div class="pes-dialog" id="pesDialog" role="dialog" aria-modal="true">
        <div class="pes-dialog-progress" id="pesDialogProgress" style="display:none;">
          <div class="pes-dialog-progress-fill" id="pesDialogProgressFill"></div>
        </div>
        <div class="pes-dialog-icon-strip" id="pesDialogIconStrip">
          <div class="pes-dialog-icon confirm" id="pesDialogIcon">⚠️</div>
        </div>
        <div class="pes-dialog-body">
          <div class="pes-dialog-title" id="pesDialogTitle">Confirm</div>
          <p class="pes-dialog-msg" id="pesDialogMsg"></p>
          <p class="pes-dialog-detail" id="pesDialogDetail" style="display:none;"></p>
        </div>
        <div class="pes-dialog-foot" id="pesDialogFoot"></div>
      </div>`;
    document.body.appendChild(div.firstElementChild);
    document.body.appendChild(div.lastElementChild);
  }

  let _autoTimer = null;

  function openDialog() {
    document.getElementById('pesDialogOverlay').classList.add('open');
    document.getElementById('pesDialog').classList.add('open');
  }

  function closeDialog() {
    clearTimeout(_autoTimer);
    const ov = document.getElementById('pesDialogOverlay');
    const dg = document.getElementById('pesDialog');
    if (ov) ov.classList.remove('open');
    if (dg) dg.classList.remove('open');
  }

  function setDialog({ icon, iconClass, title, msg, detail, foot, progress }) {
    injectDialogHtml();
    // Icon
    const iconEl = document.getElementById('pesDialogIcon');
    if (iconEl) { iconEl.textContent = icon || ''; iconEl.className = 'pes-dialog-icon ' + (iconClass || 'confirm'); }
    const iconStrip = document.getElementById('pesDialogIconStrip');
    if (iconStrip) iconStrip.style.display = icon ? 'flex' : 'none';
    // Title
    document.getElementById('pesDialogTitle').textContent = title || '';
    // Message
    document.getElementById('pesDialogMsg').innerHTML = msg || '';
    // Detail
    const detEl = document.getElementById('pesDialogDetail');
    if (detEl) { detEl.textContent = detail || ''; detEl.style.display = detail ? 'block' : 'none'; }
    // Foot buttons
    document.getElementById('pesDialogFoot').innerHTML = foot || '';
    // Progress bar
    const prog = document.getElementById('pesDialogProgress');
    const fill = document.getElementById('pesDialogProgressFill');
    if (prog) prog.style.display = progress ? 'block' : 'none';
    if (fill && progress) {
      fill.style.animation = 'none';
      void fill.offsetWidth; // reflow
      fill.style.animation = '';
    }
  }

  // ── PUBLIC API ────────────────────────────────────

  /** Standard confirm: two buttons — Yes / Cancel */
  window.pesConfirm = function(msg, onYes, onNo, opts) {
    opts = opts || {};
    setDialog({
      icon: opts.icon || '⚠️',
      iconClass: 'confirm',
      title: opts.title || 'Confirm Action',
      msg,
      detail: opts.detail || '',
      foot: `
        <button class="pes-dialog-btn pes-dialog-btn-cancel" onclick="window._pesDialogNo()">
          ${opts.cancelLabel || 'Cancel'}
        </button>
        <button class="pes-dialog-btn pes-dialog-btn-confirm" onclick="window._pesDialogYes()">
          ${opts.confirmLabel || 'Confirm'}
        </button>`
    });
    window._pesDialogYes = function() { closeDialog(); if (typeof onYes === 'function') onYes(); };
    window._pesDialogNo  = function() { closeDialog(); if (typeof onNo  === 'function') onNo(); };
    openDialog();
  };

  /** Danger confirm — red confirm button */
  window.pesDanger = function(msg, confirmLabel, onYes, onNo, opts) {
    opts = opts || {};
    setDialog({
      icon: opts.icon || '🗑',
      iconClass: 'danger',
      title: opts.title || 'Are You Sure?',
      msg,
      detail: opts.detail || '',
      foot: `
        <button class="pes-dialog-btn pes-dialog-btn-cancel" onclick="window._pesDialogNo()">Cancel</button>
        <button class="pes-dialog-btn pes-dialog-btn-danger" onclick="window._pesDialogYes()">
          ${confirmLabel || 'Delete'}
        </button>`
    });
    window._pesDialogYes = function() { closeDialog(); if (typeof onYes === 'function') onYes(); };
    window._pesDialogNo  = function() { closeDialog(); if (typeof onNo  === 'function') onNo(); };
    openDialog();
  };

  /** Alert: one OK button */
  window.pesAlert = function(msg, onOk, opts) {
    opts = opts || {};
    setDialog({
      icon: opts.icon || 'ℹ️',
      iconClass: opts.iconClass || 'info',
      title: opts.title || 'Notice',
      msg,
      detail: opts.detail || '',
      foot: `<button class="pes-dialog-btn pes-dialog-btn-ok" onclick="window._pesDialogOk()">
        ${opts.okLabel || 'OK'}
      </button>`
    });
    window._pesDialogOk = function() { closeDialog(); if (typeof onOk === 'function') onOk(); };
    openDialog();
  };

  /** Success: auto-dismisses after 2.5s with a progress bar */
  window.pesSuccess = function(title, detail, onOk) {
    setDialog({
      icon: '✓',
      iconClass: 'success',
      title: title || 'Saved',
      msg: detail || 'Your changes have been applied.',
      detail: '',
      foot: `<button class="pes-dialog-btn pes-dialog-btn-ok" onclick="window._pesDialogOk()">OK</button>`,
      progress: true
    });
    window._pesDialogOk = function() { closeDialog(); if (typeof onOk === 'function') onOk(); };
    openDialog();
    clearTimeout(_autoTimer);
    _autoTimer = setTimeout(() => {
      closeDialog();
      if (typeof onOk === 'function') onOk();
    }, 2500);
  };

  // Close on overlay click
  document.addEventListener('click', function(e) {
    if (e.target && e.target.id === 'pesDialogOverlay') {
      if (typeof window._pesDialogNo === 'function') window._pesDialogNo();
      else closeDialog();
    }
  });

  // Close on Escape
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && document.getElementById('pesDialog')?.classList.contains('open')) {
      if (typeof window._pesDialogNo === 'function') window._pesDialogNo();
      else closeDialog();
    }
  });

})();

// ── APPLY FOOTER CONFIG FROM localStorage ─────────────────
// Reads pes_footer_config and patches the live footer DOM:
// email, phone, location, hours, and all social link hrefs.
function applyFooterConfig() {
  try {
    var cfg = JSON.parse(localStorage.getItem('pes_footer_config') || 'null');
    if (!cfg) return;

    var footer = document.getElementById('footer-main');
    if (!footer) return;

    // ── Contact items ───────────────────────────────
    if (cfg.email) {
      var emailLinks = footer.querySelectorAll('a[href^="mailto:"]');
      emailLinks.forEach(function(a) {
        a.href = 'mailto:' + cfg.email;
        a.textContent = cfg.email;
      });
    }
    if (cfg.phone) {
      var phoneLinks = footer.querySelectorAll('a[href^="tel:"]');
      phoneLinks.forEach(function(a) {
        a.href = 'tel:' + cfg.phone.replace(/\s+/g, '');
        a.textContent = cfg.phone;
      });
    }
    if (cfg.location) {
      var locItems = footer.querySelectorAll('.footer-contact-item');
      locItems.forEach(function(p) {
        if (p.textContent.includes('📍') || p.querySelector('.footer-contact-icon')?.textContent === '📍') {
          var icon = p.querySelector('.footer-contact-icon');
          if (icon) {
            p.innerHTML = '';
            p.appendChild(icon);
            p.appendChild(document.createTextNode(cfg.location));
          } else {
            p.textContent = '📍 ' + cfg.location;
          }
        }
      });
    }
    if (cfg.hours) {
      var hourItems = footer.querySelectorAll('.footer-contact-item');
      hourItems.forEach(function(p) {
        if (p.textContent.includes('🕐') || p.querySelector('.footer-contact-icon')?.textContent === '🕐') {
          var icon = p.querySelector('.footer-contact-icon');
          if (icon) {
            p.innerHTML = '';
            p.appendChild(icon);
            p.appendChild(document.createTextNode(cfg.hours));
          } else {
            p.textContent = '🕐 ' + cfg.hours;
          }
        }
      });
    }

    // ── Social links ────────────────────────────────
    var socials = cfg.socials || cfg.social || {};
    var socialMap = {
      instagram: { selector: 'a[href*="instagram.com"]', base: 'https://instagram.com/' },
      facebook:  { selector: 'a[href*="facebook.com"]',  base: 'https://facebook.com/' },
      twitter:   { selector: 'a[href*="twitter.com"]',   base: 'https://twitter.com/' },
      tiktok:    { selector: 'a[href*="tiktok.com"]',    base: 'https://tiktok.com/@' },
      whatsapp:  { selector: 'a[href*="wa.me"]',         base: 'https://wa.me/' },
      youtube:   { selector: 'a[href*="youtube.com"]',   base: 'https://youtube.com/@' },
    };

    Object.keys(socialMap).forEach(function(platform) {
      var handle = socials[platform];
      if (!handle) return;
      var info = socialMap[platform];
      var link = footer.querySelector(info.selector);
      if (link) {
        // Build a clean URL: if handle already looks like a full URL keep it, else prepend base
        link.href = (handle.startsWith('http') ? handle : info.base + handle.replace(/^[@\/]+/, ''));
      }
    });

    // ── Footer brand tagline / description (optional) ──
    if (cfg.tagline) {
      var tagline = footer.querySelector('.footer-tagline');
      if (tagline) tagline.textContent = cfg.tagline;
    }
    if (cfg.description) {
      var desc = footer.querySelector('.footer-text');
      if (desc) desc.textContent = cfg.description;
    }
    if (cfg.siteName) {
      var logo = footer.querySelector('.footer-logo');
      if (logo) logo.textContent = cfg.siteName;
    }

  } catch (e) { /* footer config errors must never break the page */ }
}


document.addEventListener('DOMContentLoaded', function() {
  injectSharedFooter();
  applyFooterConfig();
  initSharedSatMap();
});
