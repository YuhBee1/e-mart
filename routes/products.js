const express = require('express');
const Product = require('../models/Product');
const { protect, adminOnly, optionalAuth } = require('../middleware/auth');
const multer = require('multer');

const router = express.Router();

// Configure multer for image uploads
const upload = multer({
  dest: 'uploads/products/',
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images allowed'));
    }
  }
});

// ══ GET ALL PRODUCTS ══
router.get('/', optionalAuth, async (req, res) => {
  try {
    const { category, search, sort, page = 1, limit = 20, featured } = req.query;
    let query = { isActive: true, isDeleted: false };

    // Filter by category
    if (category) {
      query.category = category;
    }

    // Filter by featured
    if (featured === 'true') {
      query.isFeatured = true;
    }

    // Search
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    // Sorting
    let sortQuery = { createdAt: -1 };
    if (sort === 'price-asc') sortQuery = { price: 1 };
    if (sort === 'price-desc') sortQuery = { price: -1 };
    if (sort === 'newest') sortQuery = { createdAt: -1 };
    if (sort === 'rating') sortQuery = { rating: -1 };

    // Pagination
    const skip = (page - 1) * limit;

    const [products, total] = await Promise.all([
      Product.find(query)
        .sort(sortQuery)
        .skip(skip)
        .limit(parseInt(limit))
        .select('-isDeleted'),
      Product.countDocuments(query)
    ]);

    res.json({
      success: true,
      products,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching products',
      error: error.message
    });
  }
});

// ══ GET SINGLE PRODUCT ══
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id)
      .populate('createdBy', 'firstName lastName email');

    if (!product || product.isDeleted) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    res.json({
      success: true,
      product
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching product',
      error: error.message
    });
  }
});

// ══ CREATE PRODUCT (Admin Only) ══
router.post('/', protect, adminOnly, upload.array('images', 5), async (req, res) => {
  try {
    const {
      name, description, shortDescription, price, costPrice, discount,
      category, subCategory, tags, brand, sku, stock, quantity,
      isFeatured, badge, warranty, weight
    } = req.body;

    // Validate required fields
    if (!name || !description || !price || !category) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: name, description, price, category'
      });
    }

    // Process uploaded images
    const images = req.files?.map((file, index) => ({
      url: `${process.env.APP_URL || 'http://localhost:3000'}/uploads/products/${file.filename}`,
      isMain: index === 0
    })) || [];

    const product = new Product({
      name,
      description,
      shortDescription,
      price: parseFloat(price),
      costPrice: costPrice ? parseFloat(costPrice) : undefined,
      discount: discount ? parseFloat(discount) : 0,
      category,
      subCategory,
      tags: tags ? tags.split(',').map(t => t.trim()) : [],
      brand,
      sku,
      stock,
      quantity: quantity ? parseInt(quantity) : 0,
      isFeatured: isFeatured === 'true',
      badge,
      warranty,
      weight,
      images,
      mainImage: images[0]?.url,
      createdBy: req.user._id
    });

    await product.save();

    res.status(201).json({
      success: true,
      message: 'Product created successfully',
      product
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating product',
      error: error.message
    });
  }
});

// ══ UPDATE PRODUCT (Admin Only) ══
router.put('/:id', protect, adminOnly, upload.array('images', 5), async (req, res) => {
  try {
    let product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Update fields
    const updateData = req.body;
    if (updateData.price) updateData.price = parseFloat(updateData.price);
    if (updateData.discount) updateData.discount = parseFloat(updateData.discount);
    if (updateData.quantity) updateData.quantity = parseInt(updateData.quantity);

    // Handle new images
    if (req.files && req.files.length > 0) {
      const newImages = req.files.map((file, index) => ({
        url: `${process.env.APP_URL || 'http://localhost:3000'}/uploads/products/${file.filename}`,
        isMain: index === 0
      }));
      product.images = [...(product.images || []), ...newImages];
      product.mainImage = newImages[0]?.url;
    }

    product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });

    res.json({
      success: true,
      message: 'Product updated successfully',
      product
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating product',
      error: error.message
    });
  }
});

// ══ DELETE PRODUCT (Admin Only) ══
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { isDeleted: true, updatedBy: req.user._id },
      { new: true }
    );

    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    res.json({
      success: true,
      message: 'Product deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting product',
      error: error.message
    });
  }
});

// ══ GET FEATURED PRODUCTS ══
router.get('/featured/list', optionalAuth, async (req, res) => {
  try {
    const products = await Product.find({
      isFeatured: true,
      isActive: true,
      isDeleted: false
    }).limit(6);

    res.json({
      success: true,
      products
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching featured products',
      error: error.message
    });
  }
});

module.exports = router;
