const User = require("../models/users");

const getAllUser = async (req, res) => {
  try {
    var users = await User.find({ isAdmin: false });
    console.log(users);
    res.status(200).json(users);
  } catch (error) {
    console.log("sorry");
    res.status(500).json(error);
  }
};

module.exports = {
  getAllUser,
};
