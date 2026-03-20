/**
 * PARAMOUNT E-STORE CRYPTO PAYMENT MODULE
 * 
 * Handles cryptocurrency payments across multiple gateways
 * Supports: Coinbase, BTCPay, NOWPayments, Binance Pay, Crypto.com
 */

class CryptoPayment {
  constructor(config = FORMS_CONFIG.cryptoPayment) {
    this.config = config;
    this.provider = config.provider;
    this.isEnabled = config.enabled;
    this.pendingInvoices = new Map();
    
    if (this.isEnabled) {
      this.initProvider();
    }
  }

  /**
   * Initialize the selected crypto provider
   */
  initProvider() {
    console.log(`🔐 Initializing crypto payment with provider: ${this.provider}`);
    
    switch (this.provider) {
      case 'coinbase':
        this.initCoinbase();
        break;
      case 'btcpay':
        this.initBTCPay();
        break;
      case 'nowpayments':
        this.initNOWPayments();
        break;
      case 'binance':
        this.initBinance();
        break;
      case 'cryptocom':
        this.initCryptoCom();
        break;
      default:
        console.warn(`Unknown crypto provider: ${this.provider}`);
    }
  }

  /**
   * CREATE PAYMENT INVOICE
   */
  async createInvoice(orderData) {
    try {
      console.log('💰 Creating crypto invoice for order:', orderData);

      const response = await fetch(
        FORMS_CONFIG.api.baseUrl + FORMS_CONFIG.api.createCryptoInvoice,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            provider: this.provider,
            orderId: orderData.orderId,
            amount: orderData.totalAmount,
            currency: orderData.currency || 'USD',
            cryptoCurrency: orderData.cryptoCurrency || 'BTC',
            customerEmail: orderData.customerEmail,
            customerName: orderData.customerName,
            description: orderData.description || 'Order Payment',
            returnUrl: window.location.href,
            cancelUrl: window.location.href
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to create invoice');
      }

      const invoice = await response.json();
      this.pendingInvoices.set(invoice.invoiceId, {
        ...invoice,
        createdAt: new Date(),
        status: 'pending'
      });

      console.log('✅ Invoice created:', invoice);
      return invoice;
    } catch (error) {
      console.error('❌ Invoice creation failed:', error);
      throw error;
    }
  }

  /**
   * CHECK PAYMENT STATUS
   */
  async checkPaymentStatus(invoiceId) {
    try {
      const response = await fetch(
        FORMS_CONFIG.api.baseUrl + 
        FORMS_CONFIG.api.checkPaymentStatus.replace('{invoiceId}', invoiceId)
      );

      const status = await response.json();
      
      if (this.pendingInvoices.has(invoiceId)) {
        this.pendingInvoices.get(invoiceId).status = status.status;
      }

      return status;
    } catch (error) {
      console.error('❌ Failed to check payment status:', error);
      throw error;
    }
  }

  /**
   * POLL PAYMENT STATUS
   */
  async pollPaymentStatus(invoiceId, maxAttempts = 360, interval = 10000) {
    let attempts = 0;

    return new Promise((resolve, reject) => {
      const poller = setInterval(async () => {
        attempts++;

        try {
          const status = await this.checkPaymentStatus(invoiceId);

          if (status.isPaid || status.status === 'completed') {
            clearInterval(poller);
            resolve(status);
          } else if (attempts >= maxAttempts) {
            clearInterval(poller);
            reject(new Error('Payment polling timeout'));
          }
        } catch (error) {
          if (attempts >= maxAttempts) {
            clearInterval(poller);
            reject(error);
          }
        }
      }, interval);
    });
  }

  /**
   * GET SUPPORTED CRYPTOCURRENCIES
   */
  getSupportedCryptos() {
    return this.config.supportedCryptos;
  }

  /**
   * FORMAT CRYPTO AMOUNT
   */
  formatCryptoAmount(amount, decimals = 8) {
    return parseFloat(amount).toFixed(decimals);
  }

  /**
   * CONVERT FIAT TO CRYPTO
   */
  async convertFiatToCrypto(fiatAmount, crypto) {
    try {
      const response = await fetch(
        `https://api.coinbase.com/v2/prices/${crypto}-USD/spot`
      );
      const data = await response.json();
      const rate = parseFloat(data.data.amount);
      return fiatAmount / rate;
    } catch (error) {
      console.error('❌ Crypto conversion failed:', error);
      throw error;
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // PROVIDER-SPECIFIC INITIALIZATIONS
  // ═══════════════════════════════════════════════════════════════

  initCoinbase() {
    console.log('🪙 Setting up Coinbase Commerce...');
    // Coinbase will be initialized via their hosted checkout
    // API calls handled by backend
  }

  initBTCPay() {
    console.log('₿ Setting up BTCPay Server...');
    // BTCPay uses their hosted invoice system
    // API calls handled by backend
  }

  initNOWPayments() {
    console.log('💳 Setting up NOWPayments...');
    // NOWPayments payment method initialization
    window.nowPaymentsApi = {
      createPaymentForm: (invoiceId) => {
        // Load NOWPayments form
        const script = document.createElement('script');
        script.src = 'https://nowpayments.io/embeds/nowpayments.js';
        document.body.appendChild(script);
      }
    };
  }

  initBinance() {
    console.log('🔶 Setting up Binance Pay...');
    // Binance Pay SDK initialization
    if (!window.BinancePay) {
      const script = document.createElement('script');
      script.src = 'https://pay.binance.com/web-sdk/bnbpay.js';
      document.body.appendChild(script);
    }
  }

  initCryptoCom() {
    console.log('🔵 Setting up Crypto.com Pay...');
    // Crypto.com Pay SDK initialization
    window.CryptocomPay = {
      apiKey: this.config.cryptocom.publishableKey,
      environment: 'production'
    };
  }
}

/**
 * CREATE PAYMENT FORM HTML
 */
function createCryptoPaymentForm(invoice, cryptoCurrency = 'BTC') {
  return `
    <div class="crypto-payment-form">
      <div class="payment-header">
        <h3>💰 Complete Your Payment in Crypto</h3>
        <p>Invoice #${invoice.invoiceId}</p>
      </div>

      <div class="payment-details">
        <div class="detail-row">
          <span>Amount (USD):</span>
          <strong>$${invoice.amount.toFixed(2)}</strong>
        </div>
        <div class="detail-row">
          <span>Cryptocurrency:</span>
          <strong>${cryptoCurrency}</strong>
        </div>
        <div class="detail-row">
          <span>Crypto Amount:</span>
          <strong id="cryptoAmount">Loading...</strong>
        </div>
        <div class="detail-row">
          <span>Status:</span>
          <strong id="paymentStatus">⏳ Pending</strong>
        </div>
      </div>

      <div class="qr-code-container" id="qrContainer">
        <!-- QR code will be injected here -->
      </div>

      <div class="payment-address">
        <label>Send exactly this amount to:</label>
        <div class="address-box">
          <code id="paymentAddress">${invoice.paymentAddress}</code>
          <button onclick="copyToClipboard('${invoice.paymentAddress}')" class="copy-btn">
            📋 Copy Address
          </button>
        </div>
      </div>

      <div class="payment-info">
        <p>
          <strong>Confirmations Required:</strong> 
          ${FORMS_CONFIG.cryptoPayment.confirmationRequired}
        </p>
        <p>
          <strong>Expires:</strong> 
          ${new Date(invoice.expiresAt).toLocaleTimeString()}
        </p>
      </div>

      <div class="payment-status-tracker">
        <div id="confirmationProgress" class="progress">
          <div class="progress-bar"></div>
        </div>
        <p id="confirmationText">Waiting for payment confirmation...</p>
      </div>

      <div class="payment-help">
        <details>
          <summary>Need help paying with crypto?</summary>
          <ul>
            <li>Make sure you send exactly <strong id="requiredAmount">0 BTC</strong></li>
            <li>From a wallet you control (not exchange)</li>
            <li>Wait for network confirmations</li>
            <li>Payment will be confirmed automatically</li>
          </ul>
        </details>
      </div>
    </div>
  `;
}

/**
 * POLLING MANAGER
 */
class PaymentPoller {
  constructor(cryptoPayment, invoiceId, onSuccess, onError) {
    this.cryptoPayment = cryptoPayment;
    this.invoiceId = invoiceId;
    this.onSuccess = onSuccess;
    this.onError = onError;
    this.isActive = false;
  }

  start() {
    if (this.isActive) return;
    this.isActive = true;

    console.log('⏱️ Starting payment polling...');

    this.cryptoPayment
      .pollPaymentStatus(this.invoiceId)
      .then((status) => {
        console.log('✅ Payment confirmed!', status);
        this.isActive = false;
        if (this.onSuccess) this.onSuccess(status);
      })
      .catch((error) => {
        console.error('❌ Payment polling error:', error);
        this.isActive = false;
        if (this.onError) this.onError(error);
      });
  }

  stop() {
    this.isActive = false;
  }
}

/**
 * UTILITY FUNCTIONS
 */
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert('✅ Address copied to clipboard!');
  });
}

function formatCryptoAddress(address) {
  return address.substring(0, 10) + '...' + address.substring(address.length - 10);
}

/**
 * EXPORT
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CryptoPayment, PaymentPoller, createCryptoPaymentForm };
}
