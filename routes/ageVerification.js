const express = require('express');
const { body, validationResult } = require('express-validator');
const AgeVerification = require('../models/AgeVerification');

const router = express.Router();

// Validation rules
const ageVerificationValidation = [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('whatsappNumber').notEmpty().withMessage('WhatsApp number is required'),
  body('dateOfBirth').notEmpty().withMessage('Date of birth is required')
];

// ══ VERIFY AGE ══
router.post('/verify', ageVerificationValidation, async (req, res) => {
  try {
    // Check validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { firstName, lastName, email, whatsappNumber, dateOfBirth } = req.body;

    // Check if already verified
    const existingVerification = await AgeVerification.findOne({ email });
    if (existingVerification && existingVerification.isVerified) {
      return res.status(200).json({
        success: true,
        message: 'Already verified',
        verified: true,
        age: existingVerification.age
      });
    }

    // Calculate age
    const birthDate = new Date(dateOfBirth);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }

    // Check if 18+
    if (age < 18) {
      return res.status(403).json({
        success: false,
        message: 'You must be 18 or older to access adult items',
        verified: false,
        age: age,
        reason: 'underage'
      });
    }

    // Create or update verification record
    let verification = await AgeVerification.findOneAndUpdate(
      { email },
      {
        firstName,
        lastName,
        email,
        whatsappNumber,
        dateOfBirth: new Date(dateOfBirth),
        age,
        isVerified: true,
        canAccessAdultItems: true,
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent'),
        updatedAt: new Date()
      },
      { new: true, upsert: true }
    );

    // Store in session/localStorage
    res.json({
      success: true,
      message: 'Age verification successful!',
      verified: true,
      age: age,
      verificationId: verification._id,
      expiresAt: verification.expiresAt
    });
  } catch (error) {
    console.error('Age verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Age verification failed',
      error: error.message
    });
  }
});

// ══ CHECK VERIFICATION STATUS ══
router.get('/check/:email', async (req, res) => {
  try {
    const { email } = req.params;

    const verification = await AgeVerification.findOne({ 
      email,
      isVerified: true,
      expiresAt: { $gt: new Date() } // Not expired
    });

    if (verification) {
      return res.json({
        success: true,
        verified: true,
        age: verification.age,
        canAccessAdultItems: true
      });
    }

    res.json({
      success: true,
      verified: false,
      message: 'Not verified or verification expired'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error checking verification',
      error: error.message
    });
  }
});

// ══ GET ALL VERIFIED USERS (Admin Only) ══
router.get('/admin/list', async (req, res) => {
  try {
    const verifications = await AgeVerification.find({ isVerified: true })
      .select('-userAgent')
      .sort({ verificationDate: -1 })
      .limit(100);

    res.json({
      success: true,
      total: verifications.length,
      verifications
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching verifications',
      error: error.message
    });
  }
});

// ══ GET VERIFICATION STATISTICS ══
router.get('/admin/stats', async (req, res) => {
  try {
    const totalVerified = await AgeVerification.countDocuments({ isVerified: true });
    const totalUnverified = await AgeVerification.countDocuments({ isVerified: false });
    const expiredSoon = await AgeVerification.countDocuments({
      expiresAt: {
        $gte: new Date(),
        $lte: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // Next 30 days
      }
    });

    const ageDistribution = await AgeVerification.aggregate([
      { $match: { isVerified: true } },
      { 
        $group: {
          _id: {
            $cond: [
              { $lt: ['$age', 25] },
              '18-24',
              {
                $cond: [
                  { $lt: ['$age', 35] },
                  '25-34',
                  {
                    $cond: [
                      { $lt: ['$age', 50] },
                      '35-49',
                      '50+'
                    ]
                  }
                ]
              }
            ]
          },
          count: { $sum: 1 }
        }
      }
    ]);

    res.json({
      success: true,
      stats: {
        totalVerified,
        totalUnverified,
        expiredSoon,
        ageDistribution
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
      error: error.message
    });
  }
});

module.exports = router;
