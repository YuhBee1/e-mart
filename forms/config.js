/**
 * PARAMOUNT E-STORE FORMS CONFIGURATION
 * 
 * Edit this file to customize your forms without touching HTML
 * All forms reference these settings
 */

const FORMS_CONFIG = {
  // Company Information
  company: {
    name: 'Paramount E-mart',
    website: 'https://www.paramountdigitalservices.com',
    email: 'support@paramountdigitalservices.com',
    phone: '+234 800 000 0000',
    tagline: '📍 Premium Online Shopping'
  },

  // Branding
  branding: {
    logoPath: '../../images/logo.png',
    primaryColor: '#0288d1',
    secondaryColor: '#00bcd4',
    backgroundColor: 'linear-gradient(135deg, #0f3460 0%, #16213e 100%)',
    accentColor: '#27ae60',
    errorColor: '#e74c3c'
  },

  // API Endpoints (Update these to point to your backend)
  api: {
    baseUrl: process.env.API_URL || 'http://localhost:3000/api',
    
    // Contact Form
    contactForm: '/contact-form',
    
    // Support Tickets
    supportTickets: '/support-tickets',
    supportTicketStatus: '/support-tickets/{id}/status',
    
    // Reviews
    productReviews: '/product-reviews',
    getProductReviews: '/products/{id}/reviews',
    
    // Newsletter
    newsletter: '/newsletter/subscribe',
    newsletterUnsubscribe: '/newsletter/unsubscribe',
    
    // Feedback
    feedback: '/feedback',
    
    // Orders (for receipt generator)
    getOrder: '/orders/{id}',
    searchOrders: '/orders/search',
    
    // Email service (if using)
    sendEmail: '/email/send',
    
    // Crypto Payment
    createCryptoInvoice: '/crypto/create-invoice',
    checkPaymentStatus: '/crypto/check-status/{invoiceId}',
    getPaymentMethods: '/crypto/payment-methods'
  },

  // Email Settings
  email: {
    enabled: false, // Set to true when backend email is ready
    provider: 'nodemailer', // 'nodemailer', 'sendgrid', 'mailgun'
    from: 'noreply@paramountdigitalservices.com',
    admin: 'admin@paramountdigitalservices.com',
    notifications: true
  },

  // Crypto Payment Settings ⭐ REPLACE FLUTTERWAVE
  cryptoPayment: {
    enabled: false, // Set to true when crypto gateway is ready
    provider: 'coinbase', // Options: 'coinbase', 'btcpay', 'nowpayments', 'binance', 'cryptocom'
    
    // Coinbase Commerce
    coinbase: {
      apiKey: process.env.COINBASE_API_KEY || '',
      webhookSecret: process.env.COINBASE_WEBHOOK_SECRET || '',
      apiUrl: 'https://api.commerce.coinbase.com'
    },
    
    // BTCPay Server
    btcpay: {
      storeId: process.env.BTCPAY_STORE_ID || '',
      apiKey: process.env.BTCPAY_API_KEY || '',
      serverUrl: process.env.BTCPAY_SERVER_URL || 'https://your-btcpay-instance.com',
      webhookSecret: process.env.BTCPAY_WEBHOOK_SECRET || ''
    },
    
    // NOWPayments
    nowpayments: {
      apiKey: process.env.NOWPAYMENTS_API_KEY || '',
      ipnSecret: process.env.NOWPAYMENTS_IPN_SECRET || '',
      apiUrl: 'https://api.nowpayments.io/v1'
    },
    
    // Binance Pay
    binance: {
      apiKey: process.env.BINANCE_PAY_API_KEY || '',
      secretKey: process.env.BINANCE_PAY_SECRET_KEY || '',
      apiUrl: 'https://bpay.binanceapi.com'
    },
    
    // Crypto.com Pay
    cryptocom: {
      publishableKey: process.env.CRYPTOCOM_PUBLISHABLE_KEY || '',
      secretKey: process.env.CRYPTOCOM_SECRET_KEY || '',
      apiUrl: 'https://api.pay.crypto.com'
    },
    
    // Supported Cryptocurrencies
    supportedCryptos: [
      'BTC',      // Bitcoin
      'ETH',      // Ethereum
      'USDT',     // Tether (USD)
      'USDC',     // USD Coin
      'BNB',      // Binance Coin
      'XRP',      // Ripple
      'DOGE',     // Dogecoin
      'ADA',      // Cardano
      'SOL',      // Solana
      'AVAX'      // Avalanche
    ],
    
    // Payment Settings
    confirmationRequired: 1, // Number of confirmations needed
    confirmationTimeout: 3600, // 1 hour in seconds
    invoiceExpiry: 900, // 15 minutes in seconds
    
    // Webhook Settings
    webhookUrl: process.env.CRYPTO_WEBHOOK_URL || '/api/crypto/webhook',
    enableWebhooks: true
  },

  // Form Messages
  messages: {
    contact: {
      success: '✓ Thank you! Your message has been sent. We\'ll get back to you soon!',
      error: 'Error sending message. Please try again.',
      sending: 'Sending your message...'
    },
    
    support: {
      success: '✓ Support ticket created! Your ticket number is: {ticketId}',
      error: 'Error creating support ticket. Please try again.',
      sending: 'Creating your support ticket...'
    },
    
    review: {
      success: '✓ Thank you for your review! Your feedback helps other customers.',
      error: 'Error submitting review. Please try again.',
      sending: 'Submitting your review...'
    },
    
    newsletter: {
      success: '✓ Welcome! Check your email for confirmation. Don\'t forget to check spam!',
      error: 'Error subscribing. Please try again.',
      sending: 'Subscribing you to our newsletter...'
    },
    
    feedback: {
      success: '✓ Thank you for your feedback! We really appreciate your input.',
      error: 'Error submitting feedback. Please try again.',
      sending: 'Submitting your feedback...'
    },
    
    receipt: {
      success: 'Receipt generated successfully!',
      error: 'Receipt not found. Please check your Purchase ID.',
      loading: 'Searching for your receipt...'
    }
  },

  // Form Validation Rules
  validation: {
    email: {
      required: true,
      pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
      message: 'Please enter a valid email address'
    },
    
    phone: {
      required: true,
      pattern: /^[\d\s\-+()]+$/,
      minLength: 10,
      message: 'Please enter a valid phone number'
    },
    
    name: {
      required: true,
      minLength: 2,
      maxLength: 100,
      message: 'Name must be between 2 and 100 characters'
    },
    
    message: {
      required: true,
      minLength: 10,
      maxLength: 5000,
      message: 'Message must be between 10 and 5000 characters'
    }
  },

  // Receipt Generator Configuration
  receipt: {
    // Update this to point to your API
    ordersEndpoint: '/api/orders',
    
    // Currency settings
    currency: 'NGN',
    currencySymbol: '₦',
    
    // Receipt settings
    includeTrackingNumber: true,
    includePaymentMethod: true,
    includeTaxBreakdown: true,
    
    // Sample orders for testing (feel free to add/remove)
    sampleOrders: {
      'PES-123456-ABC': true,
      'ORDER-2026-001': true,
      'PES-202603-XYZ': true,
      'ORD-2026-0045': true,
      'PES-202603-DEMO': true
    }
  },

  // Newsletter Configuration
  newsletter: {
    minEmailLength: 5,
    maxEmailLength: 254,
    interests: [
      'Electronics & Gadgets',
      'Fashion & Style',
      'Home & Living',
      'Sports & Fitness'
    ],
    sendWelcomeEmail: true,
    sendConfirmationEmail: true
  },

  // Support Ticket Configuration
  support: {
    categories: [
      'Order Issue',
      'Delivery Problem',
      'Product Defect',
      'Payment Issue',
      'Refund/Return',
      'Website Bug',
      'Other'
    ],
    
    priorities: [
      'Low',
      'Medium',
      'High',
      'Urgent'
    ],
    
    autoAssignCategory: true,
    requireOrderNumber: false,
    ticketIdPrefix: 'TKT'
  },

  // Review Configuration
  review: {
    minRating: 1,
    maxRating: 5,
    minReviewLength: 10,
    maxReviewLength: 1000,
    requireVerifiedPurchase: false,
    moderationRequired: true
  },

  // Analytics & Tracking
  analytics: {
    enabled: false,
    googleAnalyticsId: '', // Add your GA ID
    trackPageViews: true,
    trackFormSubmissions: true,
    trackErrors: true
  },

  // Security Settings
  security: {
    enableCSRF: true,
    enableRateLimit: true,
    rateLimitRequests: 5,
    rateLimitWindow: 60000, // 1 minute in ms
    sanitizeInput: true,
    validateOnServer: true
  },

  // Google Sheets Integration ⭐ NEW
  googleSheets: {
    enabled: false, // Set to true when you have Sheets API setup
    spreadsheetId: '', // Your Google Sheets ID
    apiKey: '', // Your Google Sheets API Key
    sheets: {
      contact: 'Contact Submissions',
      support: 'Support Tickets',
      review: 'Product Reviews',
      newsletter: 'Newsletter Signups',
      feedback: 'Feedback',
      receipt: 'Receipt Queries'
    }
  },

  // Localization
  localization: {
    language: 'en',
    timezone: 'Africa/Lagos',
    dateFormat: 'DD/MM/YYYY',
    timeFormat: '12h', // '12h' or '24h'
    currency: 'NGN'
  },

  // Feature Flags
  features: {
    enableReceiptGenerator: true,
    enableContactForm: true,
    enableSupportTickets: true,
    enableProductReviews: true,
    enableNewsletter: true,
    enableFeedback: true,
    enableFormDrafts: true, // Save form drafts locally
    enableAutoSave: true, // Auto-save forms
    enableOfflineMode: true // Works without internet
  },

  // Logging & Debugging
  debug: {
    enabled: false, // Set to true to see console logs
    logFormSubmissions: true,
    logErrors: true,
    logApiCalls: true,
    logValidation: true
  }
};

/**
 * USAGE EXAMPLES
 * 
 * In your JavaScript files, access config like this:
 * 
 * FORMS_CONFIG.company.name
 * FORMS_CONFIG.api.contactForm
 * FORMS_CONFIG.messages.contact.success
 * FORMS_CONFIG.branding.primaryColor
 * 
 * Example in a form:
 * 
 * showSuccess(FORMS_CONFIG.messages.contact.success);
 * 
 * Example for API call:
 * 
 * fetch(FORMS_CONFIG.api.baseUrl + FORMS_CONFIG.api.contactForm, {
 *   method: 'POST',
 *   body: JSON.stringify(data)
 * })
 * 
 * Example for styling:
 * 
 * document.documentElement.style.setProperty(
 *   '--primary-color',
 *   FORMS_CONFIG.branding.primaryColor
 * )
 */

// Export for use in Node.js/modules if needed
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FORMS_CONFIG;
}
