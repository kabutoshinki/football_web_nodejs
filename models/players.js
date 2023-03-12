const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const playerSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
    },
    description: {
      type: String,
    },
    image: {
      type: String,
      required: true,
    },
    nation: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "nations",
      // required:true
    },
    club: {
      type: String,
      required: true,
    },
    position: {
      type: String,
      required: true,
    },
    goals: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    isCaptain: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

var Players = mongoose.model("players", playerSchema);

module.exports = Players;
