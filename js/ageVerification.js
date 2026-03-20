/**
 * ═══════════════════════════════════════════════════════════
 * AGE VERIFICATION MODULE — Paramount E-mart
 * ═══════════════════════════════════════════════════════════
 * Features:
 *   • 4-hour session access window (auto-expires + auto-locks)
 *   • "Verifying…" loader overlay (4–5.6 s) before success
 *   • Reusable pesVerifying() loader for any verification event
 *   • 30-day persistent record (stored in localStorage)
 * ═══════════════════════════════════════════════════════════
 */

// ═══════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════
var _AV_KEY          = 'pes_ageVerification';
var _AV_SESSION_KEY  = 'pes_age_session';       // sessionStorage
var _AV_EXPIRY_KEY   = 'pes_age_session_exp';   // sessionStorage — 4-hour timestamp
var _AV_SESSION_HOURS = 4;                       // hours of access per session
var _AV_STORE_DAYS    = 30;                      // days before re-verification required

// ═══════════════════════════════════════════════════════════
//  VERIFYING LOADER — reusable for any "processing" moment
//  Usage:
//    pesVerifying('Checking payment…', function(done) {
//      // do work, then call done('Success Title', 'Detail text');
//    });
// ═══════════════════════════════════════════════════════════
window.pesVerifying = function(loadingText, workFn, opts) {
  opts = opts || {};
  var minMs  = opts.minMs  || 4000;   // minimum loader time (ms)
  var maxMs  = opts.maxMs  || 5600;   // randomise up to maxMs
  var icon   = opts.icon   || '🔐';

  // Random duration between minMs and maxMs for a natural feel
  var duration = minMs + Math.floor(Math.random() * (maxMs - minMs));

  // ── Build loader overlay ──────────────────────────────────
  var prev = document.getElementById('pesVerifyingOverlay');
  if (prev) prev.remove();

  var overlay = document.createElement('div');
  overlay.id = 'pesVerifyingOverlay';
  overlay.innerHTML =
    '<div class="pv-box">' +
      '<div class="pv-icon-wrap">' +
        '<div class="pv-ring"></div>' +
        '<div class="pv-icon">' + icon + '</div>' +
      '</div>' +
      '<div class="pv-title" id="pvTitle">' + (loadingText || 'Verifying…') + '</div>' +
      '<div class="pv-dots"><span></span><span></span><span></span></div>' +
      '<div class="pv-bar-wrap"><div class="pv-bar" id="pvBar"></div></div>' +
      '<div class="pv-sub" id="pvSub">Please wait a moment</div>' +
    '</div>';
  document.body.appendChild(overlay);
  document.body.style.overflow = 'hidden';

  // Animate progress bar over the duration
  var bar = document.getElementById('pvBar');
  if (bar) {
    bar.style.transition = 'width ' + (duration / 1000).toFixed(1) + 's cubic-bezier(0.1,0,0.9,1)';
    requestAnimationFrame(function() {
      requestAnimationFrame(function() { bar.style.width = '95%'; });
    });
  }

  // Cycle sub-messages for a realistic feel
  var messages = [
    'Validating your details…',
    'Cross-checking records…',
    'Securing your session…',
    'Almost done…'
  ];
  var msgIdx = 0;
  var subEl = document.getElementById('pvSub');
  var msgTimer = setInterval(function() {
    msgIdx++;
    if (msgIdx < messages.length && subEl) {
      subEl.style.opacity = '0';
      setTimeout(function() {
        if (subEl) { subEl.textContent = messages[msgIdx]; subEl.style.opacity = '1'; }
      }, 300);
    }
  }, duration / (messages.length + 1));

  // ── Run the work function, then show success ──────────────
  var started  = Date.now();
  var workDone = false;
  var successTitle  = '';
  var successDetail = '';
  var successCb     = null;

  function done(title, detail, cb) {
    workDone     = true;
    successTitle  = title  || 'Verified!';
    successDetail = detail || '';
    successCb     = cb     || null;
    // If loader hasn't finished yet, wait for it
    var elapsed   = Date.now() - started;
    var remaining = Math.max(0, duration - elapsed);
    setTimeout(_showSuccess, remaining);
  }

  function _showSuccess() {
    clearInterval(msgTimer);
    // Fill bar to 100%
    if (bar) { bar.style.transition = 'width 0.3s ease'; bar.style.width = '100%'; }
    setTimeout(function() {
      _closeLoader();
      pesVerifySuccess(successTitle, successDetail, successCb);
    }, 350);
  }

  function _closeLoader() {
    var el = document.getElementById('pesVerifyingOverlay');
    if (el) {
      el.style.opacity = '0';
      setTimeout(function() { if (el.parentNode) el.remove(); }, 300);
    }
    document.body.style.overflow = '';
  }

  // Start the work
  if (typeof workFn === 'function') {
    workFn(done);
  } else {
    // No work provided — just show loader for duration then resolve
    setTimeout(function() { done('Done', ''); }, duration);
  }
};

// ── Verified success popup ────────────────────────────────
window.pesVerifySuccess = function(title, detail, onOk) {
  var prev = document.getElementById('pesVerifySuccessOverlay');
  if (prev) prev.remove();

  var overlay = document.createElement('div');
  overlay.id  = 'pesVerifySuccessOverlay';
  overlay.innerHTML =
    '<div class="pvs-box">' +
      '<div class="pvs-check-wrap">' +
        '<svg class="pvs-check-svg" viewBox="0 0 52 52">' +
          '<circle class="pvs-check-circle" cx="26" cy="26" r="25" fill="none"/>' +
          '<path   class="pvs-check-tick"   fill="none" d="M14 27 l8 8 l16-16"/>' +
        '</svg>' +
      '</div>' +
      '<div class="pvs-title">' + (title  || 'Verified!') + '</div>' +
      '<div class="pvs-detail">' + (detail || '') + '</div>' +
      '<button class="pvs-btn" id="pvsBtnOk">Continue</button>' +
    '</div>';
  document.body.appendChild(overlay);
  document.body.style.overflow = 'hidden';

  document.getElementById('pvsBtnOk').addEventListener('click', function() {
    _closeVerifySuccess();
    if (typeof onOk === 'function') onOk();
  });

  // Auto-close after 4 s
  setTimeout(function() {
    _closeVerifySuccess();
    if (typeof onOk === 'function') onOk();
  }, 4000);

  function _closeVerifySuccess() {
    var el = document.getElementById('pesVerifySuccessOverlay');
    if (el) { el.style.opacity = '0'; setTimeout(function() { if(el.parentNode) el.remove(); }, 350); }
    document.body.style.overflow = '';
  }
};


// ═══════════════════════════════════════════════════════════
//  MODAL CONTROL
// ═══════════════════════════════════════════════════════════
function openAgeVerificationModal(catName) {
  var overlay = document.getElementById('ageVerificationOverlay');
  if (!overlay) return;
  overlay.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  clearAgeMessages();
  var form = document.getElementById('ageVerificationForm');
  if (form) form.reset();
  var ageDisplay = document.getElementById('ageDisplay');
  if (ageDisplay) ageDisplay.classList.add('hidden');

  // Update the notice text to name the specific category
  var notice = document.getElementById('ageVerNotice');
  var title  = document.getElementById('ageVerTitle');
  if (catName && notice) {
    notice.innerHTML =
      'The <strong>' + catName + '</strong> category is restricted to customers ' +
      '18 years and older. Please verify your age to continue.';
  } else if (notice) {
    // Build list of all restricted categories
    var restrictedCats = [];
    if (typeof getCategories === 'function') {
      getCategories().forEach(function(c) {
        if (c.ageRestricted) restrictedCats.push(c.name);
      });
    }
    if (restrictedCats.length > 0) {
      notice.innerHTML =
        'The following categories are restricted to customers 18 and older: ' +
        '<strong>' + restrictedCats.join(', ') + '</strong>. Please verify your age.';
    } else {
      notice.innerHTML =
        'This category is restricted to customers 18 years and older. Please verify your age to continue.';
    }
  }

  // Store the requested category so we can open it after verification
  overlay._pendingCat = catName || null;
}
function openAgeVerification(catName) { openAgeVerificationModal(catName); }

function closeAgeVerification() {
  var overlay = document.getElementById('ageVerificationOverlay');
  if (overlay) {
    overlay.classList.add('hidden');
    document.body.style.overflow = '';
  }
  clearAgeMessages();
  var form = document.getElementById('ageVerificationForm');
  if (form) form.reset();
  var ageDisplay = document.getElementById('ageDisplay');
  if (ageDisplay) ageDisplay.classList.add('hidden');
}

function declineAgeVerification() {
  localStorage.setItem('adultItemsDeclined', 'true');
  closeAgeVerification();
  showToast('Age verification required to access restricted categories');
}


// ═══════════════════════════════════════════════════════════
//  FORM HANDLING
// ═══════════════════════════════════════════════════════════
function calculateAge() {
  var dateInput = document.getElementById('ageDateOfBirth').value;
  if (!dateInput) return;
  var birthDate = new Date(dateInput);
  var today     = new Date();
  var age       = today.getFullYear() - birthDate.getFullYear();
  var m         = today.getMonth() - birthDate.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) age--;
  var ageDisplay    = document.getElementById('ageDisplay');
  var calculatedAge = document.getElementById('calculatedAge');
  if (ageDisplay) {
    ageDisplay.classList.remove('hidden');
    calculatedAge.textContent = age;
    if (age >= 18) {
      ageDisplay.style.borderLeftColor = '#27ae60';
      calculatedAge.style.color = '#2ecc71';
    } else {
      ageDisplay.style.borderLeftColor = '#e74c3c';
      calculatedAge.style.color = '#ff6b6b';
    }
  }
  return age;
}

function submitAgeVerification(event) {
  event.preventDefault();
  clearAgeMessages();

  var firstName = document.getElementById('ageFirstName').value.trim();
  var lastName  = document.getElementById('ageLastName').value.trim();
  var email     = document.getElementById('ageEmail').value.trim();
  var whatsapp  = document.getElementById('ageWhatsapp').value.trim();
  var dob       = document.getElementById('ageDateOfBirth').value;
  var terms     = document.getElementById('ageTermsAgree').checked;

  if (!firstName || !lastName || !email || !whatsapp || !dob) {
    showAgeError('Please fill in all required fields'); return;
  }
  if (!terms) { showAgeError('You must agree to the terms'); return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    showAgeError('Please enter a valid email address'); return;
  }
  var age = calculateAge();
  if (age === undefined || age === null) { showAgeError('Please enter your date of birth'); return; }
  if (age < 18) {
    showAgeError('Sorry, you must be 18 or older. You are currently ' + age + ' years old.'); return;
  }

  // Hide form, close modal, then show verifying loader
  closeAgeVerification();

  // ── Show the verifying loader for 4–5.6 s, then success ──
  pesVerifying('Verifying Your Age…', function(done) {

    // Do the actual storage work while loader runs
    var verificationId = 'PES-AV-' + Date.now();
    var expiresAt      = new Date(Date.now() + _AV_STORE_DAYS * 24 * 60 * 60 * 1000).toISOString();

    grantSessionAgeAccess();
    storeAgeVerification({
      firstName: firstName, lastName: lastName,
      email: email, whatsappNumber: whatsapp,
      verified: true, age: age,
      verificationId: verificationId, expiresAt: expiresAt,
      verifiedAt: new Date().toISOString()
    });

    // Tell the loader we're done — it will wait out its minimum time then show success
    done(
      '✓ Age Verified!',
      'Welcome, ' + firstName + '! You are ' + age + ' years old.\nAccess granted for ' + _AV_SESSION_HOURS + ' hours.',
      function() {
        // Re-render store now user has access
        if (typeof renderFeaturedInline === 'function') renderFeaturedInline();
        if (typeof renderCategoryStrip  === 'function') renderCategoryStrip();
        // Auto-open the category that triggered verification
        var overlay = document.getElementById('ageVerificationOverlay');
        var pendingCat = overlay ? overlay._pendingCat : null;
        if (pendingCat && typeof openShopPopupFiltered === 'function') {
          setTimeout(function() { openShopPopupFiltered(pendingCat); }, 200);
        } else if (typeof renderShopPopup === 'function') {
          renderShopPopup();
        }
        // Build message listing all now-unlocked restricted categories
        var unlockedNames = [];
        if (typeof getCategories === 'function') {
          getCategories().forEach(function(c) {
            if (c.ageRestricted) unlockedNames.push(c.name);
          });
        }
        var msg = unlockedNames.length
          ? unlockedNames.join(', ') + ' unlocked for ' + _AV_SESSION_HOURS + ' hours 🔓'
          : 'Age-restricted categories unlocked for ' + _AV_SESSION_HOURS + ' hours 🔓';
        showToast(msg);
      }
    );
  }, { icon: '🔞', minMs: 4000, maxMs: 5600 });
}


// ═══════════════════════════════════════════════════════════
//  MESSAGE DISPLAY
// ═══════════════════════════════════════════════════════════
function showAgeError(message) {
  var el = document.getElementById('ageVerificationError');
  if (el) { el.textContent = message; el.classList.remove('hidden'); }
}
function showAgeSuccess(message) {
  var el = document.getElementById('ageVerificationSuccess');
  if (el) { el.textContent = message; el.classList.remove('hidden'); }
}
function clearAgeMessages() {
  var e = document.getElementById('ageVerificationError');
  var s = document.getElementById('ageVerificationSuccess');
  if (e) e.classList.add('hidden');
  if (s) s.classList.add('hidden');
}


// ═══════════════════════════════════════════════════════════
//  STORAGE & VERIFICATION
// ═══════════════════════════════════════════════════════════
function storeAgeVerification(data) {
  localStorage.setItem(_AV_KEY, JSON.stringify(data));
  localStorage.removeItem('adultItemsDeclined');
}

function getAgeVerification() {
  var stored = localStorage.getItem(_AV_KEY);
  if (!stored) return null;
  try {
    var data = JSON.parse(stored);
    // Check 30-day expiry
    if (new Date() > new Date(data.expiresAt)) {
      localStorage.removeItem(_AV_KEY);
      return null;
    }
    return data;
  } catch(e) { return null; }
}

// Base check — persistent record only
function _isAgeVerifiedBase() {
  var v = getAgeVerification();
  return !!(v && v.verified === true);
}

function hasDeclinedVerification() {
  return localStorage.getItem('adultItemsDeclined') === 'true';
}

function revokeAgeVerification() {
  localStorage.removeItem(_AV_KEY);
  localStorage.removeItem('adultItemsDeclined');
  revokeSessionAgeAccess();
  if (typeof renderCategoryStrip === 'function') renderCategoryStrip();
  showToast('Age verification cleared.');
}


// ═══════════════════════════════════════════════════════════
//  SESSION ACCESS — 4-HOUR WINDOW
//  grantSessionAgeAccess() stamps the expiry time.
//  isAgeVerified() checks BOTH the 30-day record AND the
//  4-hour session window. If either expires → locked.
//  _checkSessionExpiry() runs every 60 s to auto-lock.
// ═══════════════════════════════════════════════════════════
function grantSessionAgeAccess() {
  var expiresAt = Date.now() + _AV_SESSION_HOURS * 60 * 60 * 1000;
  sessionStorage.setItem(_AV_SESSION_KEY, '1');
  sessionStorage.setItem(_AV_EXPIRY_KEY, String(expiresAt));
}

function revokeSessionAgeAccess() {
  sessionStorage.removeItem(_AV_SESSION_KEY);
  sessionStorage.removeItem(_AV_EXPIRY_KEY);
}

function hasSessionAgeAccess() {
  if (sessionStorage.getItem(_AV_SESSION_KEY) !== '1') return false;
  var exp = parseInt(sessionStorage.getItem(_AV_EXPIRY_KEY) || '0');
  if (!exp || Date.now() > exp) {
    revokeSessionAgeAccess(); // auto-clear expired session
    return false;
  }
  return true;
}

// Full check: persistent record + 4-hour session window
function isAgeVerified() {
  return _isAgeVerifiedBase() && hasSessionAgeAccess();
}

// How many minutes remain in the current session
function getSessionMinutesRemaining() {
  var exp = parseInt(sessionStorage.getItem(_AV_EXPIRY_KEY) || '0');
  if (!exp) return 0;
  return Math.max(0, Math.round((exp - Date.now()) / 60000));
}

// Auto-lock check — runs every 60 s
(function _initSessionWatcher() {
  function _tick() {
    if (!hasSessionAgeAccess() && sessionStorage.getItem(_AV_SESSION_KEY) === '1') {
      // Was active, now expired → revoke and re-render
      revokeSessionAgeAccess();
      if (typeof renderCategoryStrip  === 'function') renderCategoryStrip();
      if (typeof renderFeaturedInline === 'function') renderFeaturedInline();
      showToast('Age-restricted categories have been locked. Re-verify to continue. 🔒');
    }
  }
  setInterval(_tick, 60 * 1000); // check every minute
})();


// ═══════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════
function initAgeVerification() {
  var modal = document.getElementById('ageVerificationOverlay');
  if (!modal) return;

  modal.addEventListener('click', function(e) {
    if (e.target === modal) closeAgeVerification();
  });

  var dateInput = document.getElementById('ageDateOfBirth');
  if (dateInput) {
    var today = new Date();
    var max   = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
    dateInput.max = max.toISOString().split('T')[0];
    dateInput.min = '1900-01-01';
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAgeVerification);
} else {
  initAgeVerification();
}
