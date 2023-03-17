var express = require("express");
var {
  login,
  register,
  logout,
  profile,
  updateProfile,
  editProfile,
  saveProfile,
  verifyEmail,
  confirmOtp,
  resendOTP,
  resetPassword,
} = require("../controllers/auth.js");
var uploadCloud = require("../utils/uploader.js");
var { verifyUser, verifyAdmin, verifyToken } = require("../utils/verifyToken");
let router = express.Router();

router.post("/login", login);
router.post("/register", uploadCloud.single("image"), register);
router.get("/logout", logout);
router.get("/profile/:id", profile);
router.post("/updateProfile", uploadCloud.single("image"), updateProfile);
router.post("/verifyEmail", verifyEmail);
router.post("/confirmOTP", confirmOtp);
router.post("/resendOTP", resendOTP);
router.post("/resetPassword", resetPassword);
module.exports = router;
