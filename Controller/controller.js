const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler"); // to handle async errors
const { User, Content, SoldContent,Withdrawal,Account } = require('../Model/Model'); // your database models
const bcrypt = require("bcryptjs");
require('dotenv').config();
const FormData = require('form-data');
const   axios  = require("axios");
const sharp = require('sharp');
const mongoose = require('mongoose');
const crypto = require('crypto');

const registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create username from first 4 chars of email
    const username = email.slice(0, 4);

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await User.create({ email, username, passwordHash: hashedPassword });
    if (!user) {
      return res.status(500).json({ message: 'Failed to create user' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.status(201).json({
      _id: user._id,
      username: user.username,
      email: user.email,
      token
    });
  } catch (error) {
    console.error('Register error:', error.message);
    res.status(500).json({ message: 'Server error during registration' });
  }
};


const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      _id: user._id,
      username: user.username,
      email: user.email,
      token
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ message: 'Server error during login' });
  }
};


const uploadImage = asyncHandler(async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const CLOUDFLARE_ID = process.env.CLOUDFLARE_ID;
    const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
    const cfUrl = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ID}/images/v1`;

    // 1️⃣ Original buffer (for full image)
    const originalBuffer = req.file.buffer;

    // 2️⃣ Generate blurred preview
    const previewBuffer = await sharp(originalBuffer)
      .resize(500)   // smaller resolution for preview
      .blur(20.5)      // apply heavy blur
      .toBuffer();

    // Helper function for Cloudflare upload
    const uploadToCloudflare = async (buffer, filename) => {
      const form = new FormData();
      form.append('file', buffer, {
        filename,
        contentType: req.file.mimetype,
      });
      form.append('requireSignedURLs', 'false');

      const cfRes = await axios.post(cfUrl, form, {
        headers: {
          Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
          ...form.getHeaders(),
        },
      });

      if (!cfRes.data.success) throw new Error('Cloudflare upload failed');
      return cfRes.data.result;
    };

    // 3️⃣ Upload both
    const fullRes = await uploadToCloudflare(originalBuffer, req.file.originalname);
    const previewRes = await uploadToCloudflare(previewBuffer, `preview-${req.file.originalname}`);

  const frontendURL = process.env.FRONTEND_URL || 'https://yourapp.com';
  const username = req.user.username; 
    // 4️⃣ Save content to DB
    const { title, description, price } = req.body;

    const content = new Content({
      creator: req.user.id,
      title,
      description,
      cf_image_id: fullRes.id,
      preview_url: previewRes.variants[0],
      full_url: fullRes.variants[0],
      price: Math.round((parseFloat(price) || 0) * 100),  
       shareLink: `${frontendURL}/${username}/`
    });

// make sure user model has a username
content.shareLink = `${frontendURL}/${username}/${content._id}`;

await content.save();

    res.json({ success: true, content});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});


const getUserContents = async (req, res) => {
  try {
if (!req.user.id ) {
      return res.status(404).json({ message: 'User not available' });
    }

    const contents = await Content.find({ creator: req.user.id }) // use creator field
      .populate('creator', 'username email'); // adjust fields as needed

    if (!contents || contents.length === 0) {
      return res.status(404).json({ message: 'No content found for this user' });
    }

    res.json({ contents });
  } catch (error) {
    console.error('Error fetching user contents:', error.message);
    res.status(500).json({ message: 'Server error while fetching contents' });
  }
};


const getContentById = asyncHandler(async (req, res) => {
  const content = await Content.findById(req.params.id);
  if (!content) return res.status(404).json({ error: 'Content not found' });

  if (content.isPaid ) {
    // Paid → return full content
    return res.json({
      success: true,
      unlocked: true,
      content, // all fields
    });
  } else {
    // Not paid → return only preview info
    return res.json({
      success: true,
      unlocked: false,
      content: {
        title: content.title||'',
        description: content.description||'',
        preview_url: content.preview_url,
        price: content.price,
      },
    });
  }
});


const initialisePayment = asyncHandler(async (req, res) => {
  const { contentId,buyerEmail } = req.body; // only need contentId

  if (!contentId) {
    return res.status(400).json({ error: "Content ID is required." });
  }

  try {
    // Fetch content
    const content = await Content.findById(contentId);
    if (!content) return res.status(404).json({ error: "Content not found." });

    if (content.isPaid) {
      return res.status(400).json({ error: "Content already unlocked / paid." });
    }

    const finalAmount = content.price * 100; // stored in kobo

    const metadata = {
      contentId,
      creatorId: content.creator.toString(), // useful for notifications later
    };

    // Initialize Paystack transaction
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email:buyerEmail, // Paystack requires an email; real buyer email comes via webhook
        amount: finalAmount,
        metadata,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log(response.data);
    return res.status(200).json(response.data);

  } catch (error) {
    console.error("Error initializing payment:", error.response?.data || error.message);
    return res.status(400).json({
      error: error.response?.data || "Failed to initialize payment.",
    });
  }
});


const verifyPayment = asyncHandler(async (req, res) => {
  const { reference } = req.body; 
  if (!reference) return res.status(400).json({ error: "Reference is required." });

  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    const data = response.data;

    if (data.data.status !== "success") {
      return res.status(400).json({ error: "Payment not successful." });
    }

    const transaction = data.data;
    const metadata = transaction.metadata;
    const contentId = metadata.contentId;

    // Mark content as paid
    await Content.findByIdAndUpdate(contentId, { isPaid: true });

    const content = await Content.findById(contentId).populate("creator");
    if (!content) return res.status(404).json({ error: "Content not found." });

    const full_url = content.full_url;

    // Buyer info
    const buyerEmail = transaction.customer.email;
    const buyerName = `${transaction.customer.first_name || ""} ${transaction.customer.last_name || ""}`.trim();

    // Find creator's account
    let account = await Account.findOne({ user: content.creator._id });

    if (!account) {
      // if creator doesn't have an account yet, create one
      account = await Account.create({
        user: content.creator._id,
        balance: 0,
        soldContent: [],
        withdrawals: []
      });
    }

    // check if this buyer already bought this content
    const alreadyBought = account.soldContent.some(
      (sale) => sale.content.toString() === content._id.toString() && sale.buyerEmail === buyerEmail
    );

    if (!alreadyBought) {
      account.soldContent.push({
        content: content._id,
        buyerEmail,
        amount: transaction.amount, // kobo
        reference: transaction.reference,
      });

      // increase balance only on first purchase
      account.balance += transaction.amount;

      await account.save();
    }

    res.json({
      success: true,
      message: alreadyBought 
        ? "Buyer already purchased this content. Returning content URL." 
        : "Payment verified, content unlocked & account updated.",
      contentId,
      reference,
      buyerEmail,
      buyerName,
      full_url
    });

  } catch (error) {
    console.error("Payment verification error:", error.response?.data || error.message);
    return res.status(500).json({ error: "Failed to verify payment." });
  }
});



module.exports={getUserContents,registerUser,loginUser,uploadImage,getContentById,initialisePayment,verifyPayment}