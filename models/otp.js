const mongoose = require("mongoose");
const Schema = mongoose.Schema;
var otpSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    otp: {
      type: String,
      required: true,
    },
    time: { type: Date, default: Date.now, index: { expires: 60 } },
  },
  {
    timestamps: true,
  }
);

var Otp = mongoose.model("otp", otpSchema);

module.exports = Otp;
