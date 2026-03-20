const nodemailer = require('nodemailer');

// Initialize email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Email templates
const templates = {
  // Order Confirmation
  orderConfirmation: (order, user) => ({
    subject: `Order Confirmation #${order.orderNumber}`,
    html: `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>Thank you for your order!</h2>
        <p>Hi ${user.firstName},</p>
        <p>We've received your order and it's being processed.</p>
        
        <h3>Order Details</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr style="background: #f5f5f5;">
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Order Number</th>
            <td style="padding: 10px; border: 1px solid #ddd;">${order.orderNumber}</td>
          </tr>
          <tr>
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Tracking Number</th>
            <td style="padding: 10px; border: 1px solid #ddd;">${order.trackingNumber || 'Coming soon'}</td>
          </tr>
          <tr style="background: #f5f5f5;">
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Total Amount</th>
            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">₦${order.total.toLocaleString()}</td>
          </tr>
          <tr>
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Status</th>
            <td style="padding: 10px; border: 1px solid #ddd;">${order.shippingStatus}</td>
          </tr>
        </table>

        <h3>Items Ordered</h3>
        <ul>
          ${order.items.map(item => `
            <li>${item.name} × ${item.quantity} = ₦${(item.total || item.price * item.quantity).toLocaleString()}</li>
          `).join('')}
        </ul>

        <h3>Shipping Address</h3>
        <p>
          ${order.shippingAddress.street}<br>
          ${order.shippingAddress.city}, ${order.shippingAddress.state}<br>
          ${order.shippingAddress.country}, ${order.shippingAddress.postalCode}
        </p>

        <p style="margin-top: 20px; padding: 20px; background: #e8f4f8; border-left: 4px solid #0288d1;">
          <strong>Track Your Order:</strong> Visit our website and enter tracking number ${order.trackingNumber} to get real-time updates.
        </p>

        <p style="margin-top: 30px; color: #666; font-size: 12px;">
          If you have any questions, please contact us at support@paramountdigitalservices.com<br>
          © 2026 Paramount E-mart. All rights reserved.
        </p>
      </div>
    `
  }),

  // Shipping Status Update
  shippingUpdate: (order, user) => ({
    subject: `Shipping Update: Order #${order.orderNumber}`,
    html: `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>Your Order is on its way!</h2>
        <p>Hi ${user.firstName},</p>
        <p>Your order has been shipped and is on its way to you.</p>
        
        <p><strong>Tracking Number:</strong> ${order.trackingNumber}</p>
        <p><strong>Carrier:</strong> ${order.carrier}</p>
        <p><strong>Expected Delivery:</strong> ${new Date(order.estimatedDelivery).toLocaleDateString()}</p>
        
        <p style="margin-top: 20px;">You can track your shipment in real-time on our website.</p>
        
        <p style="margin-top: 30px; color: #666; font-size: 12px;">
          © 2026 Paramount E-mart. All rights reserved.
        </p>
      </div>
    `
  }),

  // Delivery Confirmation
  deliveryConfirmation: (order, user) => ({
    subject: `Delivery Confirmed: Order #${order.orderNumber}`,
    html: `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>Your Order has been Delivered!</h2>
        <p>Hi ${user.firstName},</p>
        <p>Great news! Your order has been delivered on ${new Date(order.actualDelivery).toLocaleDateString()}.</p>
        
        <p>We hope you're satisfied with your purchase. If you have any issues, please let us know.</p>
        
        <p style="margin-top: 20px;">
          <strong>Leave a Review:</strong> Share your experience and help other customers make informed decisions.
        </p>
        
        <p style="margin-top: 30px; color: #666; font-size: 12px;">
          © 2026 Paramount E-mart. All rights reserved.
        </p>
      </div>
    `
  }),

  // Welcome Email
  welcome: (user) => ({
    subject: 'Welcome to Paramount E-mart!',
    html: `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>Welcome ${user.firstName}!</h2>
        <p>Thank you for joining Paramount E-mart. We're excited to serve you!</p>
        
        <p>With your new account, you can:</p>
        <ul>
          <li>Browse our extensive product catalog</li>
          <li>Track your orders in real-time</li>
          <li>Save your favorite products</li>
          <li>Get exclusive offers and promotions</li>
        </ul>
        
        <p style="margin-top: 20px;">
          <a href="${process.env.APP_URL || 'http://localhost:3000'}" style="background: #0288d1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
            Start Shopping
          </a>
        </p>
        
        <p style="margin-top: 30px; color: #666; font-size: 12px;">
          © 2026 Paramount E-mart. All rights reserved.
        </p>
      </div>
    `
  }),

  // Password Reset
  passwordReset: (user, resetUrl) => ({
    subject: 'Reset Your Password',
    html: `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>Password Reset Request</h2>
        <p>Hi ${user.firstName},</p>
        <p>We received a request to reset your password. Click the link below to set a new password.</p>
        
        <p style="margin-top: 20px;">
          <a href="${resetUrl}" style="background: #0288d1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
            Reset Password
          </a>
        </p>
        
        <p style="margin-top: 20px; color: #999; font-size: 12px;">
          This link will expire in 24 hours. If you didn't request this, please ignore this email.
        </p>
        
        <p style="margin-top: 30px; color: #666; font-size: 12px;">
          © 2026 Paramount E-mart. All rights reserved.
        </p>
      </div>
    `
  })
};

// Send Email Function
const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || 'noreply@paramountdigitalservices.com',
      to,
      subject,
      html
    });
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
};

// Email Service Methods
module.exports = {
  sendOrderConfirmation: async (order, user) => {
    const { subject, html } = templates.orderConfirmation(order, user);
    return sendEmail(user.email, subject, html);
  },

  sendShippingUpdate: async (order, user) => {
    const { subject, html } = templates.shippingUpdate(order, user);
    return sendEmail(user.email, subject, html);
  },

  sendDeliveryConfirmation: async (order, user) => {
    const { subject, html } = templates.deliveryConfirmation(order, user);
    return sendEmail(user.email, subject, html);
  },

  sendWelcomeEmail: async (user) => {
    const { subject, html } = templates.welcome(user);
    return sendEmail(user.email, subject, html);
  },

  sendPasswordResetEmail: async (user, resetUrl) => {
    const { subject, html } = templates.passwordReset(user, resetUrl);
    return sendEmail(user.email, subject, html);
  },

  // Admin notifications
  sendNewOrderNotification: async (adminEmail, order) => {
    return sendEmail(
      adminEmail,
      `New Order #${order.orderNumber}`,
      `
        <h2>New Order Received</h2>
        <p><strong>Order #:</strong> ${order.orderNumber}</p>
        <p><strong>Customer:</strong> ${order.customerEmail}</p>
        <p><strong>Total:</strong> ₦${order.total.toLocaleString()}</p>
        <p><strong>Payment Status:</strong> ${order.paymentStatus}</p>
        <p>Log in to the admin panel to process this order.</p>
      `
    );
  }
};
