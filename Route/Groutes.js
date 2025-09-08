
const express = require("express");
const router = express.Router();
const {registerUser,loginUser,uploadImage,getContentById,initialisePayment,verifyPayment}=require('../Controller/controller');
const {protect}=require('../Middleware/Auth')
const multer = require("multer");
const storage = multer.memoryStorage();
const uploadcloud = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max file size
  },
}).array('image', 6);

const uploadsingle = multer({ storage: multer.memoryStorage() }).single('image');

router.post('/api/register-user',registerUser)
router.post('/api/login-user',loginUser)
router.post('/api/upload-image',protect,uploadsingle,uploadImage)
router.get('/api/get-content/:id',getContentById)
router.post('/api/pay-2-view',initialisePayment)
router.post('/api/verify-payment', verifyPayment);

module.exports=router