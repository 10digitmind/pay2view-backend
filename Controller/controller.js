const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler"); // to handle async errors
const {
  User,
  Content,
  SoldContent,
  Withdrawal,
  Account,
  DeletedUser
} = require("../Model/Model"); // your database models
const bcrypt = require("bcryptjs");
require("dotenv").config();
const FormData = require("form-data");
const axios = require("axios");
const sharp = require("sharp");
const mongoose = require("mongoose");
const crypto = require("crypto");
const {sendVerificationEmail, sendPasswordResetEmail, sendPaymentAlertToCreator, sendPaymentAlertToBuyer, sendWithdrawalEmail, contactEmail} = require("../Mailsender/sender");
const { S3Client, PutObjectCommand,GetObjectCommand,DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const r2 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});
     const CLOUDFLARE_ID = process.env.CLOUDFLARE_ID;
      const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
         const cfUrl = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ID}/images/v1`;

async function getPdfSignedUrl(bucket, key) {
  const command = new GetObjectCommand({ Bucket: bucket, Key: key });
  return await getSignedUrl(r2, command, { expiresIn: 3600 }); // 1 hour
}

// delete images 
async function deleteFromCloudflare(imageId) {
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ID}/images/v1/${imageId}`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
        },
      }
    );
    const data = await res.json();
    if (!data.success) {
      console.error("Failed to delete from Cloudflare:", data.errors);
    }
  } catch (err) {
    console.error("Cloudflare delete error:", err.message);
  }
}

const uploadToCloudflare = async (fileBuffer, filename, mimetype) => {
  const form = new FormData();
  form.append("file", fileBuffer, { filename, contentType: mimetype });
  form.append("requireSignedURLs", "false");

  const cfRes = await axios.post(cfUrl, form, {
    headers: {
      Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
      ...form.getHeaders(),
    },
  });

  return cfRes.data.result.variants[0]; // returns the uploaded image URL
};

const registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Create username from first 4 chars of email
    const username = email.slice(0, 4);

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await User.create({
      email,
      username,
      passwordHash: hashedPassword,
    });
    if (!user) {
      return res.status(500).json({ message: "Failed to create user" });
    }
    const verificationToken = crypto.randomBytes(32).toString("hex");
    // Generate token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    user.emailVerificationToken = verificationToken;
    await user.save();

    await sendVerificationEmail(user.email, user.username, verificationToken);

    res.status(201).json({
      _id: user._id,
      username: user.username,
      email: user.email,
      token,
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.query;

  try {
    // 1️⃣ Find user by verification token
    const user = await User.findOne({ emailVerificationToken: token });
    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // 2️⃣ Check if already verified
    if (user.emailVerified) {
      return res.status(400).json({ message: "User already verified" });
    }

    // 3️⃣ Mark email as verified
    user.emailVerified = true;
    user.emailVerificationToken = null;
    await user.save();

    // 4️⃣ Generate JWT for login
    const authToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // 5️⃣ Send response with token
    res.status(200).json({
      message: "Email successfully verified!",
      token: authToken,
      user: {
        id: user._id,
        email: user.email,
        emailVerified: user.emailVerified,
      },
    });
  } catch (error) {
    console.error("Email verification error:", error.message);
    res.status(500).json({ message: "Unable to verify user" });
  }
};

const resendVerification = async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.emailVerified)
      return res.status(400).json({ message: "Email is already verified" });

    // Generate new token
    const verificationToken = crypto.randomBytes(32).toString("hex");
    user.emailVerificationToken = verificationToken;
    await user.save();

    // Send verification email
    await sendVerificationEmail(
      user.email,
      user.username || user.email.slice(0, 4),
      verificationToken
    );

    res.status(200).json({ message: "Verification email resent successfully" });
  } catch (error) {
    console.error("Resend verification error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found, kindly sign up" });
    }
    if (!user.emailVerified) {
      return res
        .status(400)
        .json({ message: "Email not verified" });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or  password" });
    }

    const token = jwt.sign( 
      { id: user._id, email: user.email }, 
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      _id: user._id,
      username: user.username,
      email: user.email,
      token,
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ message: "Server error during login" });
  }
};

const uploadContent = asyncHandler(async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const { mimetype, buffer, originalname } = req.file;

    let fullUrl, previewUrl;

    if (mimetype === "application/pdf") {
      // 1️⃣ Upload PDF to Cloudflare R2
      const key = `pdfs/${Date.now()}-${originalname}`;
      await r2.send(
        new PutObjectCommand({
          Bucket: process.env.R2_BUCKET_NAME,
          Key: key,
          Body: buffer,
          ContentType: "application/pdf",
        })
      );

      fullUrl = `https://${process.env.R2_BUCKET_NAME}.${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${key}`;

      // Optional: create a placeholder preview image for PDFs
      previewUrl = "https://upload.wikimedia.org/wikipedia/commons/8/87/PDF_file_icon.svg";
    } else {
      // 🖼 Handle images with Cloudflare Images API
 
   

      const previewBuffer = await sharp(buffer).resize(500).blur(40).toBuffer();

      const uploadToCloudflare = async (fileBuffer, filename) => {
        const form = new FormData();
        form.append("file", fileBuffer, { filename, contentType: mimetype });
        form.append("requireSignedURLs", "false");

        const cfRes = await axios.post(cfUrl, form, {
          headers: {
            Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
            ...form.getHeaders(),
          },
        });

        if (!cfRes.data.success) throw new Error("Cloudflare upload failed");
        return cfRes.data.result;
      };

      const fullRes = await uploadToCloudflare(buffer, originalname);
      const previewRes = await uploadToCloudflare(
        previewBuffer,
        `preview-${originalname}`
      );

      fullUrl = fullRes.variants[0];
      previewUrl = previewRes.variants[0];
    }

    const frontendURL = process.env.CLIENT_URL || "http://localhost:3000";
    const username = req.user.username;
    const { title, description, price } = req.body;

let finalTitle = title; // make a copy

if (mimetype === "application/pdf") {
  finalTitle = `${title}-pdf`;
} else {
  finalTitle = `${title}-image`;
}
    const content = new Content({
      creator: req.user.id,
      title:finalTitle,
      description,
      full_url: fullUrl,
      preview_url: previewUrl,
      price: Math.round(parseFloat(price) || 0),
     
    });
 content.shareLink = `${frontendURL}/view-content/${title}/${content._id}`,
    await content.save();

    res.json({ success: true, content });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});




const getUserContents = async (req, res) => {
  try {
    if (!req.user.id) {
      return res.status(404).json({ message: "User not available" });
    }

    const contents = await Content.find({ creator: req.user._id }) // use creator field
// adjust fields as needed

    if (!contents || contents.length === 0) {
      return res
        .status(404)
        .json({ message: "No content found for this user" });
    }

    res.json({ contents });
  } catch (error) {
    console.error("Error fetching user contents:", error.message);
    res.status(500).json({ message: "Server error while fetching contents" });
  }
};

const getContentById = asyncHandler(async (req, res) => {
  const content = await Content.findById(req.params.id);
  if (!content) return res.status(404).json({ error: "Content not found" });

  if (content.isPaid) {
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
        _id:content._id,
        title: content.title || "",
        description: content.description || "",
        preview_url: content.preview_url,
        price: content.price,
        
      },
    });
  }
});

const initialisePayment = asyncHandler(async (req, res) => {
  const { contentId, buyerEmail, platformFee } = req.body;


  if (!contentId || !buyerEmail) {
    return res.status(400).json({ error: "Content ID and buyer email are required." });
  }
  try {
    // Fetch content
    const content = await Content.findById(contentId).populate("creator");
    if (!content) return res.status(404).json({ error: "Content not found." });

    // Find creator's account
    let account = await Account.findOne({ user: content.creator._id });

    // If account exists, check soldContent for existing purchase
    if (account) {
      const existingPurchase = account.soldContent.find(
        (sale) =>
          sale.content.toString() === content._id.toString() &&
          sale.buyerEmail === buyerEmail
      );

      if (existingPurchase) {
        // Buyer already paid before → skip Paystack init
        return res.status(200).json({
          success: true,
          alreadyPaid: true,
          reference: existingPurchase.reference,
          contentId: content._id,
        });
      }
    }

    // New purchase flow
    const finalAmount = parseInt(platformFee || 0) + content.price; // amount in kobo

    const metadata = {
      contentId,
      creatorId: content.creator._id.toString(),
    };

    // Initialize Paystack transaction
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email: buyerEmail,
        amount: finalAmount*100,
        metadata,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    return res.status(200).json({
      success: true,
      alreadyPaid: false,
      ...response.data,
    });
  } catch (error) {
    console.error(
      "Error initializing payment:",
      error.response?.data || error.message
    );
    return res.status(400).json({
      error: error.response?.data || "Failed to initialize payment.",
    });
  }
});


const verifyPayment = asyncHandler(async (req, res) => {
  const { reference } = req.body;
  if (!reference)
    return res.status(400).json({ error: "Reference is required." });

  try {
    // 1️⃣ Verify payment with Paystack
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
let status = data.data.status 


    if (data.data.status !== "success") {
      return res.status(400).json({ error: "Payment not successful." });
    }

    const transaction = data.data;
    const metadata = transaction.metadata;
    const contentId = metadata.contentId.toString();



// Validate contentId first
if (!mongoose.Types.ObjectId.isValid(contentId)) {
  return res.status(400).json({ error: "Invalid content ID" });
}

    // 2️⃣ Mark content as paid
    const content = await Content.findByIdAndUpdate(
      contentId,
      { isPaid: true },
    ).populate("creator");

    if (!content) return res.status(404).json({ error: "Content not found." });

    // 3️⃣ Generate download URL
    let contentUrl = content.full_url;

    if (content.full_url.endsWith(".pdf")) {
      try {
        const url = new URL(content.full_url);
        const key = decodeURIComponent(url.pathname.slice(1));

        const command = new GetObjectCommand({
          Bucket: process.env.R2_BUCKET_NAME,
          Key: key,
        });

        contentUrl = await getSignedUrl(r2, command, { expiresIn: 3600 }); // 1 hour
      } catch (err) {
        console.error("Failed to generate signed URL:", err);
        return res
          .status(500)
          .json({ error: "Failed to generate download link" });
      }
    }

    // 4️⃣ Buyer info
    const buyerEmail = transaction.customer.email;
    const buyerName = `${transaction.customer.first_name || ""} ${
      transaction.customer.last_name || ""
    }`.trim();

    // 5️⃣ Find or create creator's account
    let account = await Account.findOne({ user: content.creator._id });
    if (!account) {
      account = await Account.create({
        user: content.creator._id,
        balance: 0,
        soldContent: [],
        withdrawals: [],
      });
    }

    // 6️⃣ Check if buyer already purchased
    const alreadyBought = account.soldContent.some(
      (sale) =>
        sale.content.toString() === content._id.toString() &&
        sale.buyerEmail === buyerEmail
    );

    if (!alreadyBought) {
      account.soldContent.push({
        content: content._id,
        buyerEmail,
        amount: transaction.amount / 100, // Convert from kobo
        reference: transaction.reference,
        title:content.title,
        status:status
      });

      // Update balance only on first purchase
      account.balance += transaction.amount / 100;
      content.soldCount += 1;
      content.viewCount += 1;

      await Promise.all([account.save(), content.save()]);
    }

    // 7️⃣ Notifications
    const contentTitle = content.title;
    const amount = transaction.amount / 100;
    const creator = await User.findById(content.creator._id);
    const creatorName = creator.username || creator.email.split("@")[0];
    const userEmail = creator.email
    const dashboardUrl =
      process.env.FRONTEND_URL?.replace(/\/$/, "") + "/dashboard";


    await sendPaymentAlertToCreator(
      userEmail,
      creatorName,
        contentTitle,
      amount,
      dashboardUrl
    );

    await sendPaymentAlertToBuyer(buyerEmail, buyerName, contentUrl, contentTitle);

    // 8️⃣ Return response
    res.json({
      success: true,
      message: alreadyBought
        ? "Buyer already purchased this content. Returning content URL."
        : "Payment verified, content unlocked & account updated.",
      contentId,
      reference,
      buyerEmail,
      buyerName,
      full_url: contentUrl,
      preview_url:content.preview_url
    });
  } catch (error) {
    console.error(
      "Payment verification error:",
      error.response?.data || error.message
    );
    return res.status(500).json({ error: "Failed to verify payment." });
  }
});







const getUserProfile = async (req, res) => {
  try {
    if(!req.user._id){
      return res.status(400).json({message:'user id requred '})
    }
    const user = await User.findById(req.user._id).select("-passwordHash");
    res.json(user);
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ message: "Server error fetching user" });
  }
};
// DELETE /api/content/:id
const deleteContent = async (req, res) => {
  const contentId = req.params.id;
  const userId = req.user.id; // assumes auth middleware sets req.user

  if (!contentId) {
    return res.status(400).json({ error: "Content ID is required." });
  }

  // Find the content
  const content = await Content.findById(contentId);
  if (!content) {
    return res.status(404).json({ error: "Content not found." });
  }

  // Delete Cloudflare Image if exists
  try {
    if (content.cf_image_id) {
      const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
      const CLOUDFLARE_ID = process.env.CLOUDFLARE_ID;

      await axios.delete(
        `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ID}/images/v1/${content.cf_image_id}`,
        {
          headers: { Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}` },
        }
      );
    }
  } catch (err) {
    console.warn("Failed to delete from Cloudflare Images:", err.message);
  }

  // Delete PDF from R2 if exists
  try {
    if (content.full_url && content.full_url.endsWith(".pdf")) {
      const url = new URL(content.full_url);
      const key = decodeURIComponent(url.pathname.slice(1)); // object key

      await r2.send(
        new DeleteObjectCommand({
          Bucket: process.env.R2_BUCKET_NAME,
          Key: key,
        })
      );

      console.log("Deleted PDF from R2:", key);
    }
  } catch (err) {
    console.warn("Failed to delete PDF from R2:", err.message);
  }

  // Delete from DB
  await Content.findByIdAndDelete(contentId);

  res.json({ success: true, message: "Content deleted successfully." });
};

 



// POST /api/auth/forgot-password
const forgotPassword = async (req, res) => {

  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  // Find the user
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ error: "No account found with this email." });
  }

  // Generate a reset token
  const resetToken = crypto.randomBytes(32).toString("hex");
  const resetTokenExpiry = Date.now() + 3600000; // 1 hour

  // Save token and expiry in user document
  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = resetTokenExpiry;
  await user.save();

  // Create reset URL
  const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
  const resetUrl = `${FRONTEND_URL}/reset-password/${resetToken}`;

 const userEmail = user.email

  await sendPasswordResetEmail(userEmail, user.username, resetUrl);

  res.json({ success: true, message: "Password reset email sent." });
}


// POST /api/reset-password
const resetPassword = async (req, res) => {

  const { token, password } = req.body;

  if (!token || !password)
    return res.status(400).json({ error: "Token and new password are required." });

  // Hash the token received from frontend

  // Find user by hashed token and check expiry
  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) return res.status(400).json({ error: "Invalid or expired token." });

  // Update password
  user.password = password; // make sure User model has pre-save hook for hashing
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  res.json({ success: true, message: "Password reset successful!" });
}

const getUserAccount = asyncHandler(async (req, res) => {
  const userId = req.user.id; // comes from JWT middleware

  let account = await Account.findOne({ user: userId });

  if (!account) {
    account = await Account.create({
      user: userId,
      balance: 0,
      soldContent: [],
      withdrawals: [],
      soldAt: new Date(),
    });
  }

  res.json({ success: true, account });
});


const requestWithdrawal = async (req, res) => {
  try {
    const { bankName, accountName, accountNumber, amount } = req.body;

    if (!bankName || !accountName || !accountNumber || !amount) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const account = await Account.findOne({user:req.user.id})
 if (!account) {
      return res.status(404).json({ message: "Account not found" });
    }

    // Check balance
    if (account.balance < amount) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    const user= await User.findById(req.user.id)

     if (!user) {
      return res.status(404).json({ message: "user not found" });
    }

const userEmail = user.email
 const existingRequest = await Withdrawal.findOne({
      user: req.user.id,
      status: "pending"
    });

    if (existingRequest) {
      return res.status(400).json({
        message: "You already have a pending withdrawal request. Please wait until it is processed."
      });
    }
    const withdrawal = new Withdrawal({
      user: req.user.id, // assuming you have auth middleware
      bankName:bankName,
      accountName:accountName,
      accountNumber:accountNumber,
      amount:amount,
    });

     account.balance -= amount;

    await account.save()

    await withdrawal.save()

    await  sendWithdrawalEmail(accountName, bankName, accountNumber, amount,userEmail)
    res.status(201).json({
      message: "Withdrawal request submitted successfully",
      withdrawal,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

const getWithdrawalHistory = async (req, res) => {
  try {
    // Find all withdrawals for the logged-in user
    const withdrawals = await Withdrawal.find({ user: req.user.id })
      .sort({ createdAt: -1 }); // Sort newest first

    // If no withdrawals found
    if (!withdrawals || withdrawals.length === 0) {
      return res.status(404).json({
        message: "No withdrawal history found"
      });
    }
    res.status(200).json({
      message: "Withdrawal history retrieved successfully",
      withdrawals,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};


const updateUserProfile = async (req, res) => {
  try {
    const { fullName, username } = req.body;
    
    let profilePic;

    // If image file is uploaded
    if (req.file) {
      profilePic = await uploadToCloudflare(
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype
      );
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      {
        ...(fullName && { fullName }),
        ...(username && { username }),
        ...(profilePic && { profilePic }),
      },
      { new: true }
    ).select("-passwordHash");

    console.log(updatedUser)

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};


const deleteUserAccount = async (req, res) => {

  const { userId } = req.params;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Delete profile image if exists
    if (user.profilePic) {
      await deleteFromCloudflare(user.profilePic);
    }

    // Get all user contents
    const contents = await Content.find({ creator: userId });

    // Delete content images from Cloudflare
// Delete user content (images + PDFs) in parallel
await Promise.all(
  contents.map(async (content) => {
    // Delete image from Cloudflare
    if (content.cf_image_id) {
      try {
        await deleteFromCloudflare(content.cf_image_id);
        console.log("Deleted image:", content.cf_image_id);
      } catch (err) {
        console.warn("Failed to delete image from Cloudflare:", err.message);
      }
    }

    // Delete PDF from Cloudflare R2
    if (content.full_url && content.full_url.endsWith(".pdf")) {
      try {
        const url = new URL(content.full_url);
        const key = decodeURIComponent(url.pathname.slice(1)); // extract object key
        await r2.send(
          new DeleteObjectCommand({
            Bucket: process.env.R2_BUCKET_NAME,
            Key: key,
          })
        );
        console.log("Deleted PDF from R2:", key);
      } catch (err) {
        console.warn("Failed to delete PDF from R2:", err.message);
      }
    }
  })
);


try {
  await DeletedUser.create({
    email: user.email,
    reason: req.body.reason || null,
  });
} catch (err) {
  console.warn("Failed to save deleted user info:", err.message);
}

 // Delete content records from DB
    await Content.deleteMany({ creator: userId });

    // Delete user record
    await User.findByIdAndDelete(userId);

    return res.json({ message: "Account and all content deleted successfully" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }

}





const contact = async (req, res) => {
  try {
    const { fullname, email, subject, message, category } = req.body;

    // Validate input
    if (!fullname || !email || !subject || !message || !category) {
      return res.status(400).json({ success: false, error: "All fields are required." });
    }

    // (Optional) simple email format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: "Invalid email address." });
    }

    // Send email via Nodemailer
    await contactEmail(fullname, email, subject, message, category);

    return res.status(200).json({ success: true, message: "Message sent successfully." });
  } catch (error) {
    console.error("Error sending contact email:", error);
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
};

module.exports = {
  getUserContents,
  registerUser,
  loginUser,
  uploadContent,
  getContentById,
  initialisePayment,
  verifyPayment,
  verifyEmail,
  resendVerification,
  getUserProfile,
  deleteContent,
  forgotPassword,
  resetPassword,
  getUserAccount,
  requestWithdrawal,
  getWithdrawalHistory,
  updateUserProfile,
  deleteUserAccount,
  contact
};