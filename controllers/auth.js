var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
const User = require("../models/users");
const cloudinary = require("cloudinary").v2;

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

module.exports = {
  register,
  login,
  logout,
  profile,
  updateProfile,
};
