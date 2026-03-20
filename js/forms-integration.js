/**
 * PARAMOUNT E-STORE — Forms Integration
 * =======================================
 * Wires all 4 embedded forms to the Google Apps Script Web App.
 * Every form submission POSTs JSON to the GAS endpoint which
 * appends a row to the correct Google Sheet.
 *
 * Web App URL:
 *   https://script.google.com/macros/s/AKfycbwqJIqjltqcZ-PdtG304wEU4qM1C2OEiBFGyhnU3P9BvMrIkN4J9xp359qj6BysLpcAhg/exec
 *
 * Each form sends a `sheet` field that tells the Apps Script
 * which tab to append the row to:
 *   Contact     → "Contact Submissions"
 *   Support     → "Support Tickets"
 *   Newsletter  → "Newsletter Signups"
 *   Reviews     → "Product Reviews"
 */

'use strict';

(function () {

  // ── Config ──────────────────────────────────────────────
  const GAS_URL = 'https://script.google.com/macros/s/AKfycbwqJIqjltqcZ-PdtG304wEU4qM1C2OEiBFGyhnU3P9BvMrIkN4J9xp359qj6BysLpcAhg/exec';

  const SHEET_NAMES = {
    contact:    'Contact Submissions',
    support:    'Support Tickets',
    newsletter: 'Newsletter Signups',
    review:     'Product Reviews',
  };

  const MESSAGES = {
    contact: {
      success: '✓ Message sent! We\'ll get back to you within 24 hours.',
      error:   '✗ Failed to send. Please try again or email us directly.',
    },
    support: {
      success: '✓ Support ticket created! Check your email for your ticket reference.',
      error:   '✗ Could not create ticket. Please try again.',
    },
    newsletter: {
      success: '✓ You\'re subscribed! Welcome to the Paramount family.',
      error:   '✗ Subscription failed. Please try again.',
    },
    review: {
      success: '✓ Review submitted! Thank you for your feedback.',
      error:   '✗ Could not submit review. Please try again.',
    },
  };

  // ── Core submit — POST to GAS, no-cors ──────────────────
  // Google Apps Script requires no-cors when called from the browser.
  // We can't read the response body in no-cors mode, so we treat
  // a network-level success as "submitted". The GAS script itself
  // handles the sheet write and can send confirmation emails.
  async function submitToGAS(formType, data) {
    const payload = {
      sheet:     SHEET_NAMES[formType] || formType,
      formType:  formType,
      timestamp: new Date().toLocaleString('en-NG', { timeZone: 'Africa/Lagos' }),
      ...data,
    };

    // Primary: fetch with no-cors (works cross-origin to GAS)
    await fetch(GAS_URL, {
      method:  'POST',
      mode:    'no-cors',   // required for GAS
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });

    // If fetch didn't throw, the request reached GAS — treat as success.
    return true;
  }

  // ── UI helpers ───────────────────────────────────────────
  function setLoading(btn, loading) {
    if (!btn) return;
    btn.disabled = loading;
    if (loading) {
      btn._origText   = btn.textContent;
      btn.textContent = '⏳ Sending…';
    } else {
      btn.textContent = btn._origText || 'Submit';
    }
  }

  function showFormMsg(containerId, type, text) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.className       = 'pes-form-msg pes-form-msg--' + type;
    el.textContent     = text;
    el.style.display   = 'block';
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    if (type === 'success') setTimeout(() => { el.style.display = 'none'; }, 6000);
  }

  function validateEmail(v) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  }

  // ── 1. CONTACT FORM ─────────────────────────────────────
  // Attached to the existing contact popup in index.html.
  // Replaces the old sendContact() stub with full GAS submission.

  window.sendContact = async function () {
    const name    = (document.getElementById('ctName')?.value    || '').trim();
    const email   = (document.getElementById('ctEmail')?.value   || '').trim();
    const phone   = (document.getElementById('ctPhone')?.value   || '').trim();
    const subject = (document.getElementById('ctSubject')?.value || '').trim();
    const message = (document.getElementById('ctMessage')?.value || '').trim();
    const msgEl   = 'ctFormMsg';

    if (!name)               { showFormMsg(msgEl, 'error', 'Please enter your name.');           return; }
    if (!validateEmail(email)){ showFormMsg(msgEl, 'error', 'Please enter a valid email.');       return; }
    if (!message || message.length < 10) { showFormMsg(msgEl, 'error', 'Please write a message (min 10 chars).'); return; }

    const btn = document.querySelector('#contactPopup .pay-btn, #contactPopup .pes-submit-btn');
    setLoading(btn, true);
    showFormMsg(msgEl, 'info', 'Sending your message…');

    try {
      await submitToGAS('contact', { name, email, phone, subject, message });
      showFormMsg(msgEl, 'success', MESSAGES.contact.success);
      ['ctName','ctEmail','ctPhone','ctSubject','ctMessage'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      setTimeout(() => closeContactPopup(), 3000);
    } catch (e) {
      showFormMsg(msgEl, 'error', MESSAGES.contact.error);
    } finally {
      setLoading(btn, false);
    }
  };

  // ── 2. NEWSLETTER FORM ───────────────────────────────────
  // Attached to #pesNewsletterForm in the footer (shared.js) and
  // to any .pes-newsletter-inline forms on the page.

  async function handleNewsletterSubmit(form) {
    const firstName = (form.querySelector('[name="firstName"], #nlFirstName')?.value || '').trim();
    const email     = (form.querySelector('[name="email"],     #nlEmail')?.value     || '').trim();
    const msgEl     = form.querySelector('.pes-form-msg') || null;
    const msgId     = msgEl?.id || ('nl-msg-' + Math.random().toString(36).slice(2));
    if (msgEl && !msgEl.id) msgEl.id = msgId;

    const interests = [...form.querySelectorAll('input[name="interests"]:checked')]
      .map(cb => cb.value).join(', ');
    const consent   = form.querySelector('input[name="consent"], input[name="agree"]')?.checked;

    if (!validateEmail(email)) {
      if (msgEl) showFormMsg(msgId, 'error', 'Please enter a valid email address.');
      else if (typeof showToast === 'function') showToast('Please enter a valid email address.');
      return;
    }
    if (!consent) {
      if (msgEl) showFormMsg(msgId, 'error', 'Please agree to receive emails.');
      else if (typeof showToast === 'function') showToast('Please tick the consent box.');
      return;
    }

    const btn = form.querySelector('button[type="submit"], .pes-submit-btn');
    setLoading(btn, true);

    try {
      await submitToGAS('newsletter', { firstName, email, interests, consent: consent ? 'Yes' : 'No' });
      if (msgEl) showFormMsg(msgId, 'success', MESSAGES.newsletter.success);
      else if (typeof showToast === 'function') showToast(MESSAGES.newsletter.success);
      form.reset();
    } catch (e) {
      if (msgEl) showFormMsg(msgId, 'error', MESSAGES.newsletter.error);
      else if (typeof showToast === 'function') showToast(MESSAGES.newsletter.error);
    } finally {
      setLoading(btn, false);
    }
  }

  window.PES_submitNewsletter = handleNewsletterSubmit;

  // ── 3. SUPPORT FORM ──────────────────────────────────────
  // Attached to #pesSupportForm on support.html.

  window.PES_submitSupport = async function (form) {
    const name        = (form.querySelector('#spName')?.value        || '').trim();
    const email       = (form.querySelector('#spEmail')?.value       || '').trim();
    const orderNum    = (form.querySelector('#spOrder')?.value       || '').trim();
    const category    = (form.querySelector('#spCategory')?.value    || '').trim();
    const priority    = (form.querySelector('#spPriority')?.value    || '').trim();
    const description = (form.querySelector('#spDescription')?.value || '').trim();
    const msgId       = 'spFormMsg';

    if (!name)                { showFormMsg(msgId, 'error', 'Please enter your name.');           return; }
    if (!validateEmail(email)){ showFormMsg(msgId, 'error', 'Please enter a valid email.');       return; }
    if (!category)            { showFormMsg(msgId, 'error', 'Please select an issue category.');  return; }
    if (!priority)            { showFormMsg(msgId, 'error', 'Please select a priority level.');   return; }
    if (description.length < 10) { showFormMsg(msgId, 'error', 'Please describe your issue (min 10 chars).'); return; }

    const btn = form.querySelector('.pes-submit-btn');
    setLoading(btn, true);
    showFormMsg(msgId, 'info', 'Creating your support ticket…');

    // Generate a ticket reference
    const ticketId = 'TKT-' + Date.now().toString(36).toUpperCase().slice(-6);

    try {
      await submitToGAS('support', {
        name, email, orderNumber: orderNum, category, priority,
        description, ticketId, status: 'Open',
      });
      showFormMsg(msgId, 'success', `✓ Ticket created! Your reference is <strong>${ticketId}</strong>. We'll reply to ${email} within 24 hours.`);
      form.reset();
    } catch (e) {
      showFormMsg(msgId, 'error', MESSAGES.support.error);
    } finally {
      setLoading(btn, false);
    }
  };

  // ── 4. PRODUCT REVIEW — hook into existing submitReview ──
  // The existing submitReview() saves to localStorage.
  // We wrap it to ALSO push to Google Sheets.

  const _origSubmitReview = window.submitReview;
  window.submitReview = function (productId) {
    // Call original first — it handles validation + localStorage
    if (typeof _origSubmitReview === 'function') {
      _origSubmitReview(productId);
    }

    // Now gather the data that was just submitted and push to Sheets
    const name     = (document.getElementById('reviewName_' + productId)?.value || '').trim();
    const text     = (document.getElementById('reviewText_' + productId)?.value || '').trim();
    const stars    = window._reviewPickedStars || 0;
    const product  = (function () {
      try {
        const p = (typeof getProducts === 'function' ? getProducts() : [])
          .find(x => String(x.id) === String(productId));
        return p ? p.name : 'Product #' + productId;
      } catch (e) { return 'Product #' + productId; }
    })();

    if (stars && name && text && text.length >= 10) {
      submitToGAS('review', {
        customerName: name,
        productId:    productId,
        productName:  product,
        rating:       stars,
        review:       text,
        recommend:    stars >= 4 ? 'Yes' : 'No',
      }).catch(() => { /* silent — local save already happened */ });
    }
  };

  // ── Auto-wire forms by ID on DOMContentLoaded ────────────
  document.addEventListener('DOMContentLoaded', function () {

    // Newsletter forms (multiple can exist — footer + header strip)
    document.querySelectorAll('.pes-newsletter-form').forEach(function (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        handleNewsletterSubmit(form);
      });
    });

    // Support form
    const spForm = document.getElementById('pesSupportForm');
    if (spForm) {
      spForm.addEventListener('submit', function (e) {
        e.preventDefault();
        window.PES_submitSupport(spForm);
      });
    }

    // Contact form (popup — button calls sendContact() directly, no submit event needed)
    // Nothing extra required here.
  });

})();
