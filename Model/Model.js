// models.js
const mongoose = require("mongoose");



const UserSchema = new mongoose.Schema({
 email: {
  type: String,
  required: true,
  unique: true,
  lowercase: true,
  index: true,
},

  passwordHash: { type: String, required: true },
 username: {
  type: String,
  required: true,
  unique: true,
  index: true,
},

  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  createdAt: { type: Date, default: Date.now },
  profilePic: String,
  fullName: { type: String, trim: true },
  // models/User.js
  resetPasswordToken: String,
  resetPasswordExpires: Date,
   social: {
  facebook: { type: String, default: "" },
  x: { type: String, default: "" },
  tiktok: { type: String, default: "" },
  snapchat: { type: String, default: "" },
  instagram: { type: String, default: "" },
},
  bio:{type: String, default: "Welcome to my profile! I share my work and updates here."}

  // other fields...
});

const ContentSchema = new mongoose.Schema({
  creator: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  title: String,
  description: String,
  cf_image_id: String, // Cloudflare Images ID
  cf_variants: Object, // any CF returned variants
  preview_url: String, // small blurred preview (you can generate or store a thumbnail)
  full_url: String,
  snippetURL:String,
  snippetURL_uid:String,
  type:String,
  isPaid: { type: Boolean, default: false },
  price: { type: Number, default: 0 }, // amount in kobo (Paystack expects smallest unit)
  viewCount: { type: Number, default: 0 },
  soldCount: { type: Number, default: 0 },
  shareLink: { type: String },
  createdAt: { type: Date, default: Date.now },
  videoDuration:Number,
  isReady:{type:Boolean, default:false},

  
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
  accountNumber: {
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
  status: { type: String, default: "Pending" },// Paystack transaction reference
   notified: { type: Boolean, default: false },
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

const deletedUserSchema = new mongoose.Schema({
  email: { type: String, required: true },
  reason: { type: String },
  deletedAt: { type: Date, default: Date.now },
});



const VideoSchema = new mongoose.Schema({
  creator: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  title: String,
  description: String,
  cf_video_id: String, // optional if using Cloudflare Stream later
  encrypted_url: String, // encrypted video URL (R2)
  preview_url: String, // static thumbnail or blurred preview
  duration: { type: Number, default: 0 }, // in seconds
  isPaid: { type: Boolean, default: false },
  price: { type: Number, default: 0 },
  viewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

module.exports = {
  User: mongoose.model("User", UserSchema),
  Content: mongoose.model("Content", ContentSchema),
  Withdrawal: mongoose.model("Withdrawal", withdrawalSchema),
  SoldContent: mongoose.model("SoldContent", soldContentSchema),
  Account: mongoose.model("Account", accountSchema),
  DeletedUser: mongoose.model("DeletedUser", deletedUserSchema),
  VideoSchema: mongoose.model("Video", VideoSchema)
};

