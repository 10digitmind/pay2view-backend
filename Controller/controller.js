const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler"); // to handle async errors
const {
  User,
  Content,
  Withdrawal,
  Account,
  DeletedUser,

} = require("../Model/Model"); // your database models
const bcrypt = require("bcryptjs");
require("dotenv").config();
const FormData = require("form-data");
const axios = require("axios");
const sharp = require("sharp");
const mongoose = require("mongoose");
const crypto = require("crypto");
const {sendVerificationEmail, sendPasswordResetEmail, sendPaymentAlertToCreator, sendPaymentAlertToBuyer, sendWithdrawalEmail, contactEmail,signupAlert,confirmWithdrawal,Test} = require("../Mailsender/sender");
const { S3Client, PutObjectCommand,GetObjectCommand,DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const{encrypt,decrypt,} = require('../Controller/Encryption')


const fs = require("fs");

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





 async function generateSnippetURL(videoUID, ) {

  try {
    // 1️⃣ Get video metadata

    
    // 2️⃣ Call Clip API
    const clipRes = await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ID}/stream/clip`,
      {
        clippedFromVideoUID: videoUID,
        startTimeSeconds: 0,
        endTimeSeconds: 3
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.CLOUDFLARE_STREAM_TOKEN}`,
          "Content-Type": "application/json"
        }
      }
    );

    // 3️⃣ Return snippet HLS URL
    const snippetURL = clipRes.data.result.playback.hls;
    const snippetURL_uid =clipRes. data.result.uid;

    return {snippetURL,snippetURL_uid };

  } catch (err) {
    console.error("Failed to generate snippet URL:", err.response?.data || err.message);
    throw err;
  }
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

//uplaod to cloud flare
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

// register user 
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

// verifyEmail
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

    let name = user.username
    let email = user.email
    
    await signupAlert(name, email)

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

// resend verification
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

//login user
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "nvalid email or  password" });
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




// upload

const uploadToCloudflareStream = async (fileBuffer, originalname) => {
  try {
    // Step 1: Request a direct upload URL from Cloudflare
    const directUploadRes = await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ID}/stream/direct_upload`,
      { maxDurationSeconds: 3600 },
      {
        headers: {
          Authorization: `Bearer ${process.env.CLOUDFLARE_STREAM_TOKEN}`,
          "Content-Type": "application/json",
        },
      }
    );

    if (!directUploadRes.data.success) throw new Error("Failed to get direct upload URL");

    const { uploadURL, uid } = directUploadRes.data.result;

    // Step 2: Upload the video buffer directly to that URL
    await axios.post(uploadURL, fileBuffer, {
      headers: {
        "Content-Type": "application/octet-stream",
      },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    });

    // Step 3: Cloudflare automatically generates preview thumbnails
    const previewUrl = `https://videodelivery.net/${uid}/thumbnails/thumbnail.jpg?time=5s`;

    return { uid, previewUrl };
  } catch (err) {
    console.error("Cloudflare Stream direct upload error:", err.response?.data || err.message);
    throw err;
  }
};





// uplaod content 
const uploadContent = asyncHandler(async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const { mimetype, buffer, originalname } = req.file;
    const extension = originalname.split(".").pop().toLowerCase();

    const isVideo =
      mimetype.startsWith("video/") ||
      ["mp4", "mov", "avi", "mkv", "webm"].includes(extension);

    let type;
    if (mimetype === "application/pdf") {
      type = "pdf";
    } else if (isVideo) {
      type = "video";
    } else {
      type = "image";
    }

    // ---------- VIDEO LIMIT ----------
    if (type === "video") {
      const contents = await Content.find({ creator: req.user._id });
      const userVideoCount = contents.filter(c => c.type === "video").length;
      if (userVideoCount >= 3) {
        return res.status(400).json("You can only upload up to 3 videos.");
      }
    }

    // ---------- UPLOAD FILE ----------
    let fullUrl;
    let previewUrl;

    if (type === "pdf") {
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
      previewUrl = "https://upload.wikimedia.org/wikipedia/commons/8/87/PDF_file_icon.svg";

    } else if (type === "video") {
      const directUploadRes = await axios.post(
        `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ID}/stream/direct_upload`,
        { maxDurationSeconds: 60 },
        {
          headers: {
            Authorization: `Bearer ${process.env.CLOUDFLARE_STREAM_TOKEN}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (!directUploadRes.data.success)
        throw new Error("Failed to get Cloudflare direct upload URL");

      const { uploadURL, uid } = directUploadRes.data.result;

      const form = new FormData();
      form.append("file", buffer, { filename: originalname, contentType: mimetype });
      await axios.post(uploadURL, form, {
        headers: form.getHeaders(),
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      });

      const encryptedUID = encrypt(uid);
      fullUrl = encryptedUID;
      previewUrl = `https://videodelivery.net/${encryptedUID}/thumbnails/thumbnail.jpg?time=5s`;

    } else {
      // IMAGE
      const previewBuffer = await sharp(buffer).resize(500).blur(60).toBuffer();

      const uploadToCloudflare = async (fileBuffer, filename) => {
        const form = new FormData();
        form.append("file", fileBuffer, { filename, contentType: mimetype });
        form.append("requireSignedURLs", "false");

        const cfRes = await axios.post(process.env.CLOUDFLARE_IMAGES_URL, form, {
          headers: {
            Authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
            ...form.getHeaders(),
          },
        });

        if (!cfRes.data.success) throw new Error("Cloudflare upload failed");
        return cfRes.data.result;
      };

      const fullRes = await uploadToCloudflare(buffer, originalname);
      const previewRes = await uploadToCloudflare(previewBuffer, `preview-${originalname}`);

      fullUrl = encrypt(fullRes.variants[0]);
      previewUrl = previewRes.variants[0];
    }

    // ---------- SAVE TO DB ----------
    const { title, description, price } = req.body;
    const frontendURL = process.env.CLIENT_URL || "http://localhost:3000";

    const finalTitle = `${title}-${type}`;
    const content = new Content({
      creator: req.user.id,
      title: finalTitle,
      description,
      full_url: fullUrl,
      preview_url: previewUrl,
      price: Math.round(parseFloat(price) || 0),
      type, // ✅ save type
    });

    content.shareLink = `${frontendURL}/view-content/${encodeURIComponent(title)}/${content._id}`;
    await content.save();

    res.json({ success: true, content });
  } catch (err) {
    console.error("Upload content error:", err.response?.data || err.message);
    res.status(500).json({
      error: "Server error",
      details: err.response?.data || err.message,
    });
  }
});






const getVideoPlaybackURL = asyncHandler(async (req, res) => {
  const { videoId } = req.params;

  // token valid for 1 hour
  const token = jwt.sign(
    {
      sub: videoId,
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    process.env.CLOUDFLARE_STREAM_SIGNING_KEY
  );

  const playbackURL = `https://videodelivery.net/${videoId}/manifest/video.m3u8?token=${token}`;

  res.json({ playbackURL });
});

// get user content
const getUserContents = asyncHandler(async (req, res) => {
  try {
    if (!req.user?._id) {
      return res.status(404).json({ message: "User not available" });
    }

    const contents = await Content.find({ creator: req.user._id });

    if (!contents || contents.length === 0) {
      return res.status(404).json({ message: "No content found for this user" });
    }

  
    // Loop through contents to decrypt URLs and fetch duration if needed
    const processedContents = await Promise.all(
      contents.map(async (content) => {
        let fullUrl = content.full_url;

        // Decrypt image/video URLs if needed
        if (
          (content.title && content.title.endsWith("-image")) ||
          (content.preview_url && content.preview_url.includes("videodelivery.net"))
        ) {
          try {
            fullUrl = decrypt(content.full_url);
          } catch (err) {
            console.error(`Failed to decrypt content ID ${content._id}:`, err.message);
          }
        }

        // Fetch duration only if preview exists and videoDuration is missing
        if (content.preview_url?.includes("videodelivery.net") && !content.videoDuration) {
          try {
            const uid = decrypt(content.full_url); // your decrypt function
            const response = await axios.get(
              `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ID}/stream/${uid}`,
              {
                headers: {
                  Authorization: `Bearer ${process.env.CLOUDFLARE_STREAM_TOKEN}`,
                },
              }
            );
            content.videoDuration = response.data.result.duration || 0;
            await content.save();
          } catch (err) {
            console.error(`Failed to fetch duration for content ID ${content._id}:`, err.message);
          }
        }

        return {
          ...content.toObject(),
          full_url: fullUrl,
        };
      })
    );

    res.json({ contents: processedContents });
  } catch (error) {
    console.error("Error fetching user contents:", error.message);
    res.status(500).json({ message: "Server error while fetching contents" });
  }
});


// get content by id 
const getContentById = asyncHandler(async (req, res) => {
  const content = await Content.findById(req.params.id);
  if (!content) return res.status(404).json({ error: "Content not found" });

  let videoURL = '';
  if (content.preview_url?.includes('videodelivery.net')) {
    try {
      videoURL = decrypt(content.full_url); // decrypt UID for playback
    } catch (err) {
      console.error(`Failed to decrypt video UID for content ${content._id}:`, err.message);
    }
  }

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
        _id: content._id,
        title: content.title || "",
        description: content.description || "",
        preview_url: content.preview_url,
        price: content.price,
        videoUrl:videoURL, 
        videoDuration:content.videoDuration// UID for preview player
      },
    });
  }
});

// initialise payment 
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

// verifiy payment 
const verifyPayment = asyncHandler(async (req, res) => {
  let emailverification = false
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

    const transaction = response.data.data;
    if (transaction.status !== "success") {
      return res.status(400).json({ error: "Payment not successful." });
    }

    const metadata = transaction.metadata;
    const contentId = metadata.contentId?.toString();

    if (!mongoose.Types.ObjectId.isValid(contentId)) {
      return res.status(400).json({ error: "Invalid content ID" });
    }

    // 2️⃣ Mark content as paid
    const content = await Content.findByIdAndUpdate(
      contentId,
      { isPaid: true },
      { new: true }
    ).populate("creator");

    if (!content) return res.status(404).json({ error: "Content not found." });

    // 3️⃣ Generate actual download/view URL
    let contentUrl = content.full_url;
    const isVideo = content.preview_url?.includes("videodelivery.net");

    if (isVideo) {
      try {
        const uid = decrypt(content.full_url);
        contentUrl = `https://videodelivery.net/${uid}/manifest/video.m3u8`;
      } catch (err) {
        console.error("Failed to decrypt video UID:", err.message);
        return res.status(500).json({ error: "Failed to unlock full video." });
      }
    } else if (content.title.endsWith("-image")) {
      try {
        contentUrl = decrypt(content.full_url);
      } catch (err) {
        console.error("Failed to decrypt image URL:", err.message);
        return res.status(500).json({ error: "Failed to unlock content." });
      }
    } else if (content.full_url.endsWith(".pdf")) {
      try {
        const url = new URL(content.full_url);
        const key = decodeURIComponent(url.pathname.slice(1));
        const command = new GetObjectCommand({
          Bucket: process.env.R2_BUCKET_NAME,
          Key: key,
        });
        contentUrl = await getSignedUrl(r2, command, { expiresIn: 3600 });
      } catch (err) {
        console.error("Failed to generate signed URL:", err);
        return res.status(500).json({ error: "Failed to generate download link." });
      }
    }
    // 4️⃣ Buyer info
    const buyerEmail = transaction.customer.email;
    const buyerName = `${transaction.customer.first_name || ""} ${
      transaction.customer.last_name || ""
    }`.trim();

    // 5️⃣ Find or create creator’s account
    let account = await Account.findOne({ user: content.creator._id });
    if (!account) {
      account = await Account.create({
        user: content.creator._id,
        balance: 0,
        soldContent: [],
        withdrawals: [],
      });
    }

    // 6️⃣ Deduplicate soldContent & find sale
    account.soldContent = account.soldContent.filter(
      (s, i, arr) =>
        i === arr.findIndex(
          (t) => t.content.toString() === s.content.toString() && t.buyerEmail === s.buyerEmail
        )
    );

    let sale = account.soldContent.find(
      (s) => s.content.toString() === content._id.toString() && s.buyerEmail === buyerEmail
    );

    if (!sale) {
      sale = {
        content: content._id,
        buyerEmail,
        amount: transaction.amount / 100,
        reference: transaction.reference,
        title: content.title,
        status: transaction.status,
        notified: false,
      };
      account.soldContent.push(sale);

      // update balances & counts
      account.balance += transaction.amount / 100;
      content.soldCount += 1;
      content.viewCount += 1;

      await Promise.all([account.save(), content.save()]);
    }

    // 7️⃣ Send notifications only once
    if (!sale.notified) {
      const creator = await User.findById(content.creator._id);
      const creatorName = creator.username || creator.email.split("@")[0];
      const dashboardUrl =
        process.env.CLIENT_URL?.replace(/\/$/, "") + "/dashboard";

      await Promise.all([
        sendPaymentAlertToCreator(
          creator.email,
          creatorName,
          content.title,
          transaction.amount / 100,
          dashboardUrl
        ),
        sendPaymentAlertToBuyer(
          buyerName,
          content.title,
          contentUrl,
          buyerEmail
        ),
      ]);

      
      sale.notified = true;
      await account.save();
    }

    // 8️⃣ Return content info
    res.json({
      success: true,
      message: sale.notified
        ? "Payment verified, content unlocked."
        : "Buyer already has access. Returning content URL.",
      contentId,
      reference,
      buyerEmail,
      buyerName,
      full_url: contentUrl,
      preview_url: content.preview_url,
    });
  } catch (error) {
    console.error("Payment verification error:", error.response?.data || error.message);
    return res.status(500).json({ error: "Failed to verify payment." });
  }
});


// get user profile 
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

  if (!contentId) {
    return res.status(400).json({ error: "Content ID is required." });
  }

  const content = await Content.findById(contentId);
  if (!content) {
    return res.status(404).json({ error: "Content not found." });
  }

  // ---------- Delete Cloudflare Image ----------
  try {
    if (content.cf_image_id) {
      await axios.delete(
        `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ID}/images/v1/${content.cf_image_id}`,
        { headers: { Authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}` } }
      );
    }
  } catch (err) {
    console.warn("Failed to delete Cloudflare Image:", err.message);
  }

  // ---------- Delete PDF from R2 ----------
  try {
    if (content.full_url?.endsWith(".pdf")) {
      const url = new URL(content.full_url);
      const key = decodeURIComponent(url.pathname.slice(1));

      await r2.send(
        new DeleteObjectCommand({
          Bucket: process.env.R2_BUCKET_NAME,
          Key: key,
        })
      );
    }
  } catch (err) {
    console.warn("Failed to delete PDF from R2:", err.message);
  }

  // ---------- Delete Cloudflare Stream MAIN Video ----------
  try {
    const isVideo = content.preview_url?.includes("videodelivery.net");

    if (isVideo && content.full_url) {
      const mainUid = decrypt(content.full_url);

      await axios.delete(
        `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ID}/stream/${mainUid}`,
        { headers: { Authorization: `Bearer ${process.env.CLOUDFLARE_STREAM_TOKEN}` } }
      );

      console.log("Deleted MAIN video from Cloudflare Stream:", mainUid);
    }
  } catch (err) {
    console.warn("Failed to delete MAIN video:", err.message);
  }

  // ---------- Delete Cloudflare Stream SNIPPET Video ----------
  try {
    if (content.snippetURL_uid) {
      await axios.delete(
        `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ID}/stream/${content.snippetURL_uid}`,
        { headers: { Authorization: `Bearer ${process.env.CLOUDFLARE_STREAM_TOKEN}` } }
      );

      console.log("Deleted SNIPPET video from Cloudflare Stream:", content.snippetURL_uid);
    }
  } catch (err) {
    console.warn("Failed to delete SNIPPET video:", err.message);
  }

  // ---------- Delete DB Document ----------
  await Content.findByIdAndDelete(contentId);

  res.json({ success: true, message: "Content, main video, and snippet deleted successfully." });
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

// get user account 
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

// request withdrawal 
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

// get withdrawal history
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

//UPdate user 
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

// delete user account
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

// contact 
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




function emailsToArray(emailString) {
  // Split by newlines, remove empty lines and trim spaces
  return emailString
    .split(/\r?\n/)           // split on newline (works on Windows/Linux)
    .map(email => email.trim()) // remove extra spaces
    .filter(email => email);   // remove empty strings
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}






const sendMarketingEmail = async () => {
  try {
    // Get all users with verified emails
    const users = await User.find({ emailVerified: true });

    let totalSent = 0;

    for (const user of users) {
      try {
        const upload_link = 'https://www.pay2view.io/upload-content';
        await Test(user.username, user.email, upload_link); // send email
        totalSent++;
      } catch (err) {
        console.error(`Failed to send to ${user.email}:`, err.message);
      }
    }

    console.log("Total emails sent:", totalSent);
  } catch (error) {
    console.error("Error in sendMarketingEmail:", error);
  }
};

// sendMarketingEmail()

async function confirmPayment(email) {
  const user = await User.findOne({ email: email });

  if (!user) {
    return console.log("user not found");
  }

  // Find pending withdrawal
  let withdrawal = await Withdrawal.findOne({
    user: user.id,
    status: "pending",
  });

  if (!withdrawal) {
    return console.log("withdrawal not found");
  }

  const name = user.username;
  const requestedAmount = withdrawal.amount;
  const feePercent = 10; // %
  const feeAmount = requestedAmount * 0.1; // actual amount
  const netAmount = requestedAmount - feeAmount;
  const date = new Date();
  const supportEmail = "payments@pay2view.io";

  // Update withdrawal status
  withdrawal.status = "completed";
  await withdrawal.save();

  console.log("withdrawal saved and updated");

  // Send confirmation email
  await confirmWithdrawal(
    email,
    name,
    requestedAmount,
    feeAmount,
    netAmount,
    date,
    supportEmail,
    feePercent
  );
}

const getVideoSnippet = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const content = await Content.findById(id);
  if (!content) return res.status(404).json({ error: "Content not found" });

  const videoUID = decrypt(content.full_url);

  // ============================
  // PAID USER → give full video
  // ============================
  if (content.isPaid) {
    return res.json({
      success: true,
      unlocked: true,
      videoURL: `https://videodelivery.net/${videoUID}/manifest/video.m3u8`,
    });
  }

  // ==================================================
  // UNPAID USER → only return snippet (generate once)
  // ==================================================

  // 1️⃣ If snippet already exists → return it
  if (content.snippetURL) {
    return res.json({
      success: true,
      unlocked: false,
      snippetURL: content.snippetURL,
      duration: 5,
    });
  }

  // 2️⃣ Generate snippet (5 sec fixed)
  try {
    const {snippetURL,snippetURL_uid} = await generateSnippetURL(videoUID);

    content.snippetURL = snippetURL;
    content.snippetURL_uid= snippetURL_uid
    await content.save();

    return res.json({
      success: true,
      unlocked: false,
      snippetURL,
      duration: 5,
    });

  } catch (err) {
    console.error("Snippet generation failed:", err);
    return res.status(500).json({ error: "Failed to generate snippet" });
  }
});




// Extract Cloudflare video ID
function extractVideoId(urlOrId) {
  if (!urlOrId.includes("/")) return urlOrId; // already an ID

  // Example: https://videodelivery.net/<ID>/thumbnails
  const parts = urlOrId.split("/");
  return parts[3]; // ID always appears after the domain
}



const checkVideoStatus = asyncHandler(async (req, res) => {
  try {
    const { videos } = req.body;

    if (!Array.isArray(videos)) {
      return res.status(400).json({ error: "videos must be an array" });
    }

    // Helper to extract UID from URL or return ID if already UID
    const extractVideoId = (urlOrId) => {
      if (urlOrId.includes("videodelivery.net")) {
        const parts = urlOrId.split("/");
        return parts[3]; // UID is always the 4th segment
      }
      return urlOrId; // assume already UID
    };

    const results = await Promise.all(
      videos.map(async (video) => {

        const id = extractVideoId(video);

        try {
          const resp = await axios.get(
            `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ID}/stream/${id}`,
            {
              headers: { Authorization: `Bearer ${process.env.CLOUDFLARE_STREAM_TOKEN}` },
            }
          );


          return {
            id,
            status: resp.data.result.status,
            ready: resp.data.result.readyToStream === true,
          };
        } catch (err) {
          console.error(`Error fetching Cloudflare video ${id}:`, err.response?.data || err.message);
          return {
            id,
            error: true,
            ready: false,
          };
        }
      })
    );

    return res.json({ results });
  } catch (err) {
    console.error("checkVideoStatus error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});











// confirmPayment("josephdonee057@gmail.com")



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
  contact,
  getVideoSnippet,
  checkVideoStatus
  


};