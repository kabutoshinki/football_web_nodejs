const { default: mongoose } = require("mongoose");
const Player = require("../models/players");
const Nation = require("../models/nations");
const cloudinary = require("cloudinary").v2;
const getAllPlayers = async (req, res) => {
  try {
    var players = await Player.find({}).populate("nation");
    const nations = await Nation.find();
    res.status(200).json(players);
  } catch (err) {
    res.status(500).json(err);
  }
};

const getPlayerById = async (req, res) => {
  try {
    const id = req.params.id;
    const player = await Player.findById(id).populate("nation");
    res.status(200).json(player);
  } catch (err) {
    res.status(500).json(err);
  }
};

const deletePlayerById = async (req, res) => {
  try {
    const id = req.params.id;
    const playerDel = await Player.findById({ _id: id });
    const publicId = playerDel.image.split("/").slice(-1)[0].split(".")[0];
    cloudinary.uploader.destroy("images/" + publicId, function (error, result) {
      if (error) {
        console.log("Error deleting image from Cloudinary:", error.message);
      } else {
        console.log("Image deleted from Cloudinary:", result);
      }
    });

    await Player.deleteOne({ _id: id });
    res.status(200).json("Delete Success");
  } catch (err) {
    if (req.file) cloudinary.uploader.destroy(file.filename);
    res.status(500).json(err);
  }
};

const createPlayer = async (req, res) => {
  try {
    let errors = [];
    const file = req.file;
    req.body.image = file?.path;
    if (req.body.isCaptain == "" || req.body.isCaptain == undefined) {
      req.body.isCaptain = false;
    }
    const checkName = await Player.find({ name: req.body.name }).count();
    console.log(checkName);
    if (checkName > 0) {
      errors.push({ msg: "Name Player Already Exist Please Try Again" });
      return res.status(401).json({ errors });
    }
    const player = await Player.create(req.body);
    res.status(200).json(player);
  } catch (err) {
    console.log("error");
    console.log(err);
    if (req.file) cloudinary.uploader.destroy(file.filename);
    res.status(500).json(err);
  }
};

const updatePlayer = async (req, res) => {
  console.log(req.file);
  let errors = [];
  try {
    console.log(req.body);
    const file = req.file;
    if (req.body.isCaptain == "" || req.body.isCaptain == undefined) {
      req.body.isCaptain = false;
    }
    const playerCheckName = await Player.findById(req.body._id);
    if (req.body.name !== playerCheckName.name) {
      const count = await Player.find({ name: req.body.name }).count();
      if (count > 0) {
        errors.push({ msg: "Name Player Already Exist Please Try Again" });
        return res.status(401).json({ errors });
      }
    }
    if (req.file !== undefined) {
      req.body.image = req.file?.path;
      const publicId = req.body.originImg.split("/").slice(-1)[0].split(".")[0];
      console.log("publicId check");
      console.log(publicId);
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
    const player = await Player.findByIdAndUpdate(req.body._id, req.body);
    res.status(200).json(player);
  } catch (error) {
    console.log(error);
    res.status(500).json("Name Player Already Exist Please Try Again");
  }
};

module.exports = {
  getAllPlayers,
  getPlayerById,
  deletePlayerById,
  createPlayer,
  updatePlayer,
};
