const mongoose = require('mongoose');

const ageVerificationSchema = new mongoose.Schema({
  // Personal Info
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Valid email required']
  },
  whatsappNumber: {
    type: String,
    required: [true, 'WhatsApp number is required'],
    match: [/^\+?[\d\s\-()]+$/, 'Valid phone number required']
  },
  
  // Age Verification
  dateOfBirth: {
    type: Date,
    required: [true, 'Date of birth is required']
  },
  age: {
    type: Number,
    required: true,
    min: [18, 'Must be 18 or older']
  },
  isVerified: {
    type: Boolean,
    default: true // Auto-verified when form submitted if 18+
  },
  verificationDate: {
    type: Date,
    default: Date.now
  },

  // Device/Browser Info
  ipAddress: String,
  userAgent: String,
  deviceId: String,

  // Status
  isActive: {
    type: Boolean,
    default: true
  },
  expiresAt: {
    type: Date,
    default: function() {
      // Expires in 365 days
      const date = new Date();
      date.setFullYear(date.getFullYear() + 1);
      return date;
    },
    index: { expireAfterSeconds: 0 } // Auto-delete after expiry
  },

  // Access
  canAccessAdultItems: {
    type: Boolean,
    default: true
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

// Calculate age before saving
ageVerificationSchema.pre('save', function(next) {
  const today = new Date();
  const birthDate = new Date(this.dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  
  this.age = age;
  
  // Only verify if 18+
  if (age < 18) {
    this.isVerified = false;
    this.canAccessAdultItems = false;
  }
  
  next();
});

// Index for quick lookups
ageVerificationSchema.index({ email: 1 });
ageVerificationSchema.index({ whatsappNumber: 1 });
ageVerificationSchema.index({ verificationDate: -1 });

module.exports = mongoose.model('AgeVerification', ageVerificationSchema);
