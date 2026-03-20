const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  // Order Reference
  orderNumber: {
    type: String,
    unique: true,
    required: true
  },
  trackingNumber: {
    type: String,
    unique: true,
    sparse: true
  },

  // Customer
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  customerEmail: String,
  customerPhone: String,

  // Items
  items: [{
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true
    },
    name: String,
    price: Number,
    quantity: {
      type: Number,
      required: true,
      min: 1
    },
    discount: Number,
    total: Number
  }],

  // Pricing
  subtotal: {
    type: Number,
    required: true,
    min: 0
  },
  tax: {
    type: Number,
    default: 0,
    min: 0
  },
  shipping: {
    type: Number,
    default: 0,
    min: 0
  },
  discount: {
    type: Number,
    default: 0,
    min: 0
  },
  couponCode: String,
  total: {
    type: Number,
    required: true,
    min: 0
  },

  // Shipping Address
  shippingAddress: {
    firstName: String,
    lastName: String,
    street: String,
    city: String,
    state: String,
    country: String,
    postalCode: String,
    phone: String
  },

  // Billing Address
  billingAddress: {
    firstName: String,
    lastName: String,
    street: String,
    city: String,
    state: String,
    country: String,
    postalCode: String
  },

  // Payment
  paymentMethod: {
    type: String,
    enum: ['crypto', 'flutterwave', 'paypal', 'bank-transfer', 'card'],
    required: true
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'refunded'],
    default: 'pending'
  },
  paymentReference: String,
  paymentDate: Date,

  // Shipping & Delivery
  shippingMethod: String,
  carrier: String,
  estimatedDelivery: Date,
  actualDelivery: Date,
  shippingStatus: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'in-transit', 'delivered', 'cancelled'],
    default: 'pending'
  },

  // Status History
  statusHistory: [{
    status: String,
    timestamp: {
      type: Date,
      default: Date.now
    },
    note: String,
    location: String
  }],

  // Additional Info
  notes: String,
  internalNotes: String,
  currency: {
    type: String,
    default: 'NGN'
  },

  // Flags
  isCompleted: {
    type: Boolean,
    default: false
  },
  isCancelled: {
    type: Boolean,
    default: false
  },
  isArchived: {
    type: Boolean,
    default: false
  },

  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Auto-calculate total
orderSchema.pre('save', function(next) {
  this.total = this.subtotal + this.tax + this.shipping - this.discount;
  next();
});

// Index for quick lookups
orderSchema.index({ customerId: 1, createdAt: -1 });
orderSchema.index({ orderNumber: 1 });
orderSchema.index({ trackingNumber: 1 });

module.exports = mongoose.model('Order', orderSchema);
