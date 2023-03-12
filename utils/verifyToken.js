var jwt = require("jsonwebtoken");
var { createError } = require("./error.js");

const verifyToken = async (req, res, next) => {
  const token = req.cookies.access_token;
  let errors = [];
  if (!token) {
    errors.push({ msg: "You are not authenticated" });
    return res.status(401).json({ errors });
  }

  jwt.verify(token, process.env.JWT, (err, user) => {
    if (err) {
      errors.push({ msg: "Token is not valid!" });
      return res.status(401).json({ errors });
    }

    req.user = user;
    console.log(user);
    next();
  });
};

const verifyUser = (req, res, next) => {
  verifyToken(req, res, () => {
    // console.log("id checked: " + req.user.id);
    if (req.user.email === req.params.email || req.user.isAdmin === false) {
      next();
    } else {
      let errors = [];
      errors.push({ msg: "You are not authorized" });
      return res.status(401).json({ errors });
    }
  });
  // console.log("id checked: " + req.params.id);
};

const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, () => {
    if (req.user.isAdmin === true) {
      next();
    } else {
      let errors = [];
      errors.push({ msg: "You are not authorized" });
      return res.status(401).json({ errors });
    }
  });
};
module.exports = {
  verifyUser,
  verifyAdmin,
  verifyToken,
};
