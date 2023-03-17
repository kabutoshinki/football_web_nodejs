const mongoose = require("mongoose");
const Schema = mongoose.Schema;
var userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    image: {
      type: String,
      default:
        "https://static.vecteezy.com/system/resources/previews/013/366/678/original/foot-ball-or-soccer-ball-icon-symbol-for-art-illustration-logo-website-apps-pictogram-news-infographic-or-graphic-design-element-format-png.png",
    },
    password: {
      type: String,
      required: true,
    },
    name: {
      type: String,
      require: true,
    },
    dob: {
      type: Date,
    },
    isAdmin: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  }
);

var Users = mongoose.model("users", userSchema);

module.exports = Users;
