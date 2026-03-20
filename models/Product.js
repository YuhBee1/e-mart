const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  // Basic Info
  name: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true,
    minlength: 3
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    minlength: 10
  },
  shortDescription: {
    type: String,
    maxlength: 200
  },

  // Pricing
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: 0
  },
  costPrice: {
    type: Number,
    min: 0
  },
  discount: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  discountedPrice: {
    type: Number,
    default: function() {
      return this.price * (1 - this.discount / 100);
    }
  },

  // Category & Tags
  category: {
    type: String,
    required: [true, 'Category is required']
  },
  subCategory: String,
  tags: [String],

  // Images
  images: [{
    url: {
      type: String,
      required: true
    },
    cloudinaryId: String,
    isMain: {
      type: Boolean,
      default: false
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  mainImage: String,

  // Stock & Inventory
  stock: {
    type: String,
    enum: ['in-stock', 'limited', 'out-of-stock'],
    default: 'in-stock'
  },
  quantity: {
    type: Number,
    default: 0,
    min: 0
  },
  lowStockThreshold: {
    type: Number,
    default: 5
  },

  // Product Details
  brand: String,
  sku: {
    type: String,
    unique: true,
    sparse: true
  },
  specifications: mongoose.Schema.Types.Mixed,
  warranty: String,
  weight: String,
  dimensions: {
    length: Number,
    width: Number,
    height: Number
  },

  // Features
  isFeatured: {
    type: Boolean,
    default: false
  },
  badge: {
    type: String,
    enum: ['BESTSELLER', 'NEW', 'HOT', 'PREMIUM', null],
    default: null
  },
  rating: {
    type: Number,
    default: 0,
    min: 0,
    max: 5
  },
  reviewCount: {
    type: Number,
    default: 0
  },

  // SEO
  seoTitle: String,
  seoDescription: String,
  seoKeywords: [String],

  // Admin & Management
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isDeleted: {
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

// Update discountedPrice before save
productSchema.pre('save', function(next) {
  this.discountedPrice = this.price * (1 - this.discount / 100);
  next();
});

// Virtual for main image
productSchema.virtual('mainImageUrl').get(function() {
  const mainImg = this.images?.find(img => img.isMain);
  return mainImg?.url || this.images?.[0]?.url || '/images/placeholder.png';
});

// Index for search
productSchema.index({ name: 'text', description: 'text', tags: 'text' });

module.exports = mongoose.model('Product', productSchema);
