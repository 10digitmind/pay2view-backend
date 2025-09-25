// models.js
const mongoose = require("mongoose");
const { title } = require("process");

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  username: { type: String, trim: true },
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  createdAt: { type: Date, default: Date.now },
  profilePic: String,
  fullName: { type: String, trim: true },
  createdAt: { type: Date, default: Date.now },
  // models/User.js
  resetPasswordToken: String,
  resetPasswordExpires: Date,

  // other fields...
});

const ContentSchema = new mongoose.Schema({
  creator: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  title: String,
  description: String,
  cf_image_id: String, // Cloudflare Images ID
  cf_variants: Object, // any CF returned variants
  preview_url: String, // small blurred preview (you can generate or store a thumbnail)
  full_url: String, // Cloudflare image URL (or returned src)
  isPaid: { type: Boolean, default: false },
  price: { type: Number, default: 0 }, // amount in kobo (Paystack expects smallest unit)
  viewCount: { type: Number, default: 0 },
  soldCount: { type: Number, default: 0 },
  shareLink: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const withdrawalSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  amount: { type: Number, required: true }, // stored in kobo
  status: {
    type: String,
    enum: ["pending", "completed", "rejected"],
    default: "pending",
  },
  createdAt: { type: Date, default: Date.now },
  processedAt: Date,
  bankName: {
    type: String,
    required: true,
  },
  accountName: {
    type: String,
    required: true,
  },
});

const soldContentSchema = new mongoose.Schema({
  content: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Content",
    required: true,
  },
  buyerEmail: String,
  amount: { type: Number, required: true }, // amount paid for this content (kobo)
  soldAt: { type: Date, default: Date.now },
  reference: String, 
  title:String,
  status: { type: String, default: "Pending" }// Paystack transaction reference
});

const accountSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    unique: true,
  },
  balance: { type: Number, default: 0 }, // current balance in kobo
  soldContent: [soldContentSchema],
  withdrawals: [withdrawalSchema],
  createdAt: { type: Date, default: Date.now },
});

module.exports = {
  User: mongoose.model("User", UserSchema),
  Content: mongoose.model("Content", ContentSchema),
  Withdrawal: mongoose.model("Withdrawal", withdrawalSchema),
  SoldContent: mongoose.model("SoldContent", soldContentSchema),
  Account: mongoose.model("Account", accountSchema),
};