var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
const User = require("../models/users");
const Otp = require("../models/otp");
const cloudinary = require("cloudinary").v2;
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const register = async (req, res, next) => {
  try {
    const email = req.body.email;
    const password = req.body.password;
    console.log(req.body);
    console.log(req.file);
    const file = req.file;
    let errors = [];
    if (!email || !password) {
      errors.push({ msg: "Please Enter all fields" });
    }

    if (password.length < 6) {
      errors.push({ msg: "Password must be at least 6 characters " });
    }

    if (errors.length > 0) {
      if (file) cloudinary.uploader.destroy(file.filename);
      return res.status(400).json({ errors: errors });
    } else {
      var userExist = await User.findOne({ email: email });
      if (userExist) {
        errors.push({ msg: "Email already exists" });
        return res.status(400).json({ errors: errors });
      } else {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);
        if (file != undefined) {
          req.body.image = file?.path;
        }
        const newUser = new User({ ...req.body, password: hash });
        const saveUser = newUser.save();
        console.log("save success");
        res.status(200).json({ message: "User registered successfully" });
      }
    }
  } catch (err) {
    console.log("error: " + err);
    return res.status(500).json({ error: err });
  }
};

const login = async (req, res, next) => {
  try {
    const email = req.body.email;
    const password = req.body.password;
    let errors = [];
    if (!email || !password) {
      errors.push({ msg: "Please Enter all fields" });
      return res.status(400).json({ errors });
    }
    if (errors.length > 0) {
      return res.status(400).json({ errors });
    } else {
      const user = await User.findOne({ email: email });
      console.log(user);
      if (!user) {
        errors.push({ msg: "User Name or Password incorrect please try again" });
        return res.status(401).json({ errors });
      } else {
        const isPasswordCorrect = await bcrypt.compareSync(req.body.password, user.password);
        console.log(isPasswordCorrect);
        if (!isPasswordCorrect) {
          errors.push({ msg: "User Name or Password incorrect please try again" });
          return res.status(401).json({ errors });
        } else {
          const token = jwt.sign(
            { email: user.email, image: user.image, id: user._id, isAdmin: user.isAdmin },
            process.env.JWT
          );
          // req.session.user = user;
          // res.cookie("user", JSON.stringify(user), { httpOnly: true });
          res
            .cookie("access_token", token, {
              httpOnly: true,
            })
            .status(200)
            .json({ details: { email: user.email, image: user.image, id: user._id, isAdmin: user.isAdmin } });
          const accessToken = req.cookies.access_token;
          // console.log("accessToken");
          // console.log(accessToken);
          // return res.status(200).json({ message: "Logged in successfully" });
        }
      }
    }
  } catch (err) {
    // next(err);
    return res.status(500).json(err);
  }
};

const logout = (req, res) => {
  req.session.destroy();
  res.clearCookie("access_token");
  res.clearCookie("user");
  res.status(200).json("Logout Success");
};

const profile = async (req, res) => {
  try {
    const id = req.params.id;
    const userProfile = await User.findById({ _id: id });
    // const isCurrentUser = req.user && req.user.id === id;

    res.status(200).json({ success: true, data: userProfile });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

const updateProfile = async (req, res) => {
  console.log("body");
  console.log(req.body);
  let errors = [];
  const file = req.file;
  const user = await User.findById({ _id: req.body._id });

  if (file !== undefined) {
    req.body.image = req.file?.path;
    const publicId = req.body.originImg.split("/").slice(-1)[0].split(".")[0];
    cloudinary.uploader.destroy("images/" + publicId, function (error, result) {
      if (error) {
        console.log("Error deleting image from Cloudinary:", error.message);
      } else {
        console.log("Image deleted from Cloudinary:", result);
      }
    });
  } else {
    req.body.image = req.body.originImg;
  }

  if (req.body.newPassword.length > 1 && !(req.body.confirmPassword.length > 1)) {
    errors.push({ msg: "Enter old Password before update new Password" });
    return res.status(400).json({ errors });
  }
  if (req.body.confirmPassword.length > 1) {
    const isPasswordCorrect = await bcrypt.compareSync(req.body.confirmPassword, req.body.password);
    if (!isPasswordCorrect) {
      errors.push({ msg: "Password not correct Please try again" });
      return res.status(400).json({ errors });
    } else {
      if (req.body.newPassword.length < 6) {
        errors.push({ msg: "New Password Length is too short please try again" });
        return res.status(400).json({ errors });
      } else if (req.body.newPassword !== req.body.confirmNewPassword) {
        errors.push({ msg: "New Password and Confirm Password is not correct please try again" });
        return res.status(400).json({ errors });
      } else if (req.body.confirmPassword === req.body.newPassword) {
        errors.push({ msg: "New Password need to be different with the Old Password" });
        return res.status(400).json({ errors });
      } else {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.newPassword, salt);
        req.body.password = hash;

        console.log(req.user);
        const userUpdate = await User.findByIdAndUpdate(req.body._id, req.body);
        res.status(200).json({ message: "User updated successfully" });
      }
    }
  } else {
    await User.findByIdAndUpdate(req.body._id, req.body);
    res.status(200).json({ message: "User updated successfully" });
  }
};

function handleSendEmail(email, otp) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "hoanghuy1vip@gmail.com",
      pass: "hpichzkexouzqifx",
    },
  });

  const mailOptions = {
    from: "hoanghuy1vip@gmail.com",
    to: email,
    subject: "Reset Password - OTP",
    html: `<p>Your OTP is ${otp}. Use this to reset your password.</p>`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}

const verifyEmail = async (req, res) => {
  try {
    const email = req.body.email;
    console.log(req.body);
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Email not found" });
    }

    const existingOtp = await Otp.findOne({ email });
    if (existingOtp) {
      // If OTP exists and is not expired, update the OTP and expiry time
      const now = new Date();
      const otp = crypto.randomInt(100000, 999999);
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(String(otp), salt);
      existingOtp.otp = hash;
      existingOtp.time = new Date(now.getTime() + 1 * 60 * 1000);
      await existingOtp.save();
      handleSendEmail(email, otp);
      console.log(otp);
      return res.status(200).json({ message: "OTP updated" });
    } else {
      const now = new Date();
      const expiryTime = new Date(now.getTime() + 5 * 60 * 1000);
      const otp = crypto.randomInt(100000, 999999);
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(String(otp), salt);
      const newOtp = new Otp({ email, otp: hash });
      await newOtp.save();
      handleSendEmail(email, otp);
      console.log(otp);
      return res.status(200).json({ message: "OTP generated" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
};

const confirmOtp = async (req, res) => {
  // Verify OTP
  try {
    const confirmOTP = req.body.otp;
    const email = req.body.email;
    const user = await User.findOne({ email });
    const verifyOtp = await Otp.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Email not found" });
    }
    if (!verifyOtp) {
      return res.status(400).json({ message: "OTP invalid or expired" });
    }

    const isOtpCorrect = await bcrypt.compareSync(confirmOTP, verifyOtp.otp);
    if (!isOtpCorrect) {
      return res.status(400).json({ message: "OTP invalid or expired" });
    } else {
      return res.status(200).json({ message: "OTP verified", email: email });
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const resendOTP = async (req, res) => {
  try {
    const email = req.body.email;
    const user = await User.findOne({ email });

    if (!user) {
      console.log("Email not found");
      return res.status(400).json({ error: "Email not found" });
    }

    const now = new Date();
    const existingOtp = await Otp.findOne({ email });

    if (existingOtp) {
      // If OTP exists and is not expired, update the OTP and expiry time
      console.log("Existing OTP still valid");
      const otp = crypto.randomInt(100000, 999999);
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(String(otp), salt);
      console.log(otp);
      existingOtp.otp = hash;
      existingOtp.time = new Date(now.getTime() + 1 * 60 * 1000);
      await existingOtp.save();
      console.log("update success");
      handleSendEmail(email, otp);
      res.status(200).json({ message: "Re-send OTP Success please wait felt minute" });
    } else {
      const otp = crypto.randomInt(100000, 999999);
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(String(otp), salt);
      const newOtp = new Otp({ email, otp: hash });
      await newOtp.save();
      handleSendEmail(email, otp);
      console.log(otp);
      console.log("success");
      res.status(200).json({ message: "Re-send OTP Success please wait felt minute" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

const resetPassword = async (req, res) => {
  try {
    const newPassword = req.body.password;
    const confirmPassword = req.body.password_confirm;
    const email = req.body.email;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Email not found" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password is too short" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "New password and confirm password do not match" });
    }

    const isPasswordCorrect = await bcrypt.compare(newPassword, user.password);
    if (isPasswordCorrect) {
      return res.status(400).json({ error: "New password cannot be the same as the current password" });
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(newPassword, salt);
    user.password = hash;
    await user.save();

    const checkOtpExist = await Otp.findOne({ email });
    if (checkOtpExist) {
      await Otp.deleteOne({ email });
    }

    return res.status(200).json({ message: "Reset password successfully" });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: "Internal server error" });
  }
};

module.exports = {
  register,
  login,
  logout,
  profile,
  updateProfile,
  verifyEmail,
  confirmOtp,
  resendOTP,
  resetPassword,
};
