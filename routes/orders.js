const express = require('express');
const Order = require('../models/Order');
const User = require('../models/User');
const { protect, adminOnly } = require('../middleware/auth');
const emailService = require('../services/emailService');

const router = express.Router();

// Generate order number
const generateOrderNumber = () => {
  const timestamp = Date.now().toString().slice(-6);
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `PES-${timestamp}-${random}`;
};

// ══ CREATE ORDER ══
router.post('/', protect, async (req, res) => {
  try {
    const {
      items,
      subtotal,
      tax,
      shipping,
      discount,
      total,
      paymentMethod,
      shippingAddress,
      billingAddress,
      couponCode,
      notes
    } = req.body;

    // Validate required fields
    if (!items || items.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Order must contain at least one item'
      });
    }

    if (!shippingAddress) {
      return res.status(400).json({
        success: false,
        message: 'Shipping address is required'
      });
    }

    // Create order
    const orderNumber = generateOrderNumber();
    const order = new Order({
      orderNumber,
      customerId: req.user._id,
      customerEmail: req.user.email,
      customerPhone: req.user.phone,
      items,
      subtotal: parseFloat(subtotal),
      tax: parseFloat(tax) || 0,
      shipping: parseFloat(shipping) || 0,
      discount: parseFloat(discount) || 0,
      total: parseFloat(total),
      paymentMethod,
      shippingAddress,
      billingAddress: billingAddress || shippingAddress,
      couponCode,
      notes,
      statusHistory: [{
        status: 'pending',
        timestamp: new Date(),
        note: 'Order created'
      }]
    });

    await order.save();

    // Send confirmation email
    try {
      await emailService.sendOrderConfirmation(order, req.user);
    } catch (emailError) {
      console.error('Failed to send confirmation email:', emailError);
    }

    res.status(201).json({
      success: true,
      message: 'Order created successfully',
      order
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating order',
      error: error.message
    });
  }
});

// ══ GET CUSTOMER'S ORDERS ══
router.get('/my-orders', protect, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const [orders, total] = await Promise.all([
      Order.find({ customerId: req.user._id })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .populate('items.productId', 'name price'),
      Order.countDocuments({ customerId: req.user._id })
    ]);

    res.json({
      success: true,
      orders,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching orders',
      error: error.message
    });
  }
});

// ══ GET SINGLE ORDER ══
router.get('/:id', protect, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id)
      .populate('customerId', 'firstName lastName email phone')
      .populate('items.productId', 'name price images');

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Check if customer owns this order (unless admin)
    if (req.user.role !== 'admin' && order.customerId._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    res.json({
      success: true,
      order
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching order',
      error: error.message
    });
  }
});

// ══ GET ALL ORDERS (Admin) ══
router.get('/', protect, adminOnly, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, paymentStatus } = req.query;
    let query = {};

    if (status) query.shippingStatus = status;
    if (paymentStatus) query.paymentStatus = paymentStatus;

    const skip = (page - 1) * limit;

    const [orders, total] = await Promise.all([
      Order.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .populate('customerId', 'firstName lastName email'),
      Order.countDocuments(query)
    ]);

    res.json({
      success: true,
      orders,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching orders',
      error: error.message
    });
  }
});

// ══ UPDATE ORDER STATUS (Admin) ══
router.put('/:id/status', protect, adminOnly, async (req, res) => {
  try {
    const { shippingStatus, note } = req.body;

    const order = await Order.findByIdAndUpdate(
      req.params.id,
      {
        shippingStatus,
        updatedAt: new Date(),
        $push: {
          statusHistory: {
            status: shippingStatus,
            timestamp: new Date(),
            note,
            location: req.body.location
          }
        }
      },
      { new: true }
    ).populate('customerId', 'firstName lastName email');

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Send email notification if shipped or delivered
    if (shippingStatus === 'shipped') {
      try {
        await emailService.sendShippingUpdate(order, order.customerId);
      } catch (emailError) {
        console.error('Failed to send shipping update:', emailError);
      }
    } else if (shippingStatus === 'delivered') {
      try {
        await emailService.sendDeliveryConfirmation(order, order.customerId);
      } catch (emailError) {
        console.error('Failed to send delivery confirmation:', emailError);
      }
    }

    res.json({
      success: true,
      message: 'Order status updated successfully',
      order
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating order',
      error: error.message
    });
  }
});

// ══ UPDATE PAYMENT STATUS (Admin) ══
router.put('/:id/payment', protect, adminOnly, async (req, res) => {
  try {
    const { paymentStatus, paymentReference } = req.body;

    const order = await Order.findByIdAndUpdate(
      req.params.id,
      {
        paymentStatus,
        paymentReference,
        paymentDate: paymentStatus === 'completed' ? new Date() : undefined,
        updatedAt: new Date()
      },
      { new: true }
    );

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    res.json({
      success: true,
      message: 'Payment status updated successfully',
      order
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating payment',
      error: error.message
    });
  }
});

// ══ CANCEL ORDER ══
router.post('/:id/cancel', protect, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Check authorization
    if (req.user.role !== 'admin' && order.customerId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Check if order can be cancelled
    if (['shipped', 'in-transit', 'delivered'].includes(order.shippingStatus)) {
      return res.status(400).json({
        success: false,
        message: 'Cannot cancel order that has already shipped'
      });
    }

    order.isCancelled = true;
    order.shippingStatus = 'cancelled';
    order.statusHistory.push({
      status: 'cancelled',
      timestamp: new Date(),
      note: req.body.reason || 'Cancelled by customer'
    });

    await order.save();

    res.json({
      success: true,
      message: 'Order cancelled successfully',
      order
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error cancelling order',
      error: error.message
    });
  }
});

module.exports = router;
