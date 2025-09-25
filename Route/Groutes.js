const express = require("express");
const router = express.Router();
const {
  registerUser,
  loginUser,
  uploadContent,
  getContentById,
  initialisePayment,
  verifyPayment,
  verifyEmail,
  resendVerification,
  getUserProfile,
  getUserContents,
  deleteContent,
  forgotPassword,
  resetPassword,
  getUserAccount,
  requestWithdrawal,
  getWithdrawalHistory,
   updateUserProfile
} = require("../Controller/controller");
const { protect } = require("../Middleware/Auth");
const multer = require("multer");
const storage = multer.memoryStorage();
const uploadcloud = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max file size
  },
}).array("image", 6);

const uploadsingle = multer({ storage: multer.memoryStorage() }).single(
  "image"
);

router.post("/api/register-user", registerUser);
router.post("/api/login-user", loginUser);
router.post("/api/upload-content", protect, uploadsingle, uploadContent);
router.post("/api/update-user-profile", protect, uploadsingle, updateUserProfile);

router.get("/api/get-content/:id", getContentById);
router.post("/api/pay-2-view", initialisePayment);
router.post("/api/verify-payment", verifyPayment);
router.post("/api/verify-email", verifyEmail);
router.post("/api/resendverification-email", resendVerification);
router.get("/api/get-user-profile",protect, getUserProfile);
router.get("/api/get-user-content",protect, getUserContents);
router.delete("/api/delete-content/:id",protect, deleteContent);
router.post("/api/send-reset-password", forgotPassword);
router.post("/api/reset-password", resetPassword);
router.get("/api/get-user-account", protect,getUserAccount);

router.post("/api/request-withdrawals", protect,requestWithdrawal);
router.get("/api/get-withdrawal-history", protect,getWithdrawalHistory);


module.exports = router;
