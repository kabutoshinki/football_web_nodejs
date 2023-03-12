const e = require("express");
const { default: mongoose } = require("mongoose");
const Nations = require("../models/nations");
const Players = require("../models/players");
const cloudinary = require("cloudinary").v2;
const getAllNations = async (req, res) => {
  try {
    var nations = await Nations.find({});
    res.status(200).json(nations);
  } catch (err) {
    res.status(500).json(err);
  }
};

const addNation = async (req, res) => {
  try {
    let errors = [];
    const file = req.file;
    req.body.image = file?.path;

    const checkNation = await Nations.find({ name: req.body.name }).count();
    if (checkNation > 0) {
      errors.push({ msg: "Nation Name Already Existed Please Try Again" });
      return res.status(400).json({ errors });
    }

    const nation = await Nations.create(req.body);

    return res.status(200).json(nation);
  } catch (err) {
    if (req.file) cloudinary.uploader.destroy(file.filename);
    res.status(500).json(err);
  }
};

const deleteNationById = async (req, res) => {
  try {
    let errors = [];
    const id = req.params.id;
    console.log("id: " + id);
    const player = await Players.findOne({ nation: id });
    if (player) {
      errors.push({ msg: "This Nation Id Have Constraint With Player, Try Another One" });
      return res.status(500).json({ errors });
    } else {
      const nationDel = await Nations.findById({ _id: id });
      console.log(nationDel);
      if (nationDel.image !== undefined) {
        const publicId = nationDel.image.split("/").slice(-1)[0].split(".")[0];
        console.log(publicId);
        cloudinary.uploader.destroy("images/" + publicId, function (error, result) {
          if (error) {
            console.log("Error deleting image from Cloudinary:", error.message);
          } else {
            console.log("Image deleted from Cloudinary:", result);
          }
        });
      }
      await Nations.deleteOne({ _id: id });
      return res.status(200).json("Delete Success");
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json(err);
  }
};

const updateNationById = async (req, res) => {
  try {
    let errors = [];
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
      console.log(req.body.image);
      console.log("origin");
      console.log(req.body.originImg);
      req.body.image = req.body.originImg;
    }

    const getNationName = await Nations.findById(req.body._id);
    if (req.body.name !== getNationName.name) {
      const countName = await Nations.find({ name: req.body.name }).count();
      if (countName > 0) {
        errors.push({ msg: "Nation Name Already Existed Please Try Again" });
        return res.status(400).json({ errors });
      }
    }

    const nationUpdata = await Nations.findByIdAndUpdate(req.body._id, req.body);
    return res.status(200).json(nationUpdata);
  } catch (error) {
    console.log("error");
    if (req.file) cloudinary.uploader.destroy(file.filename);
    res.status(500).json(error);
  }
};

module.exports = {
  getAllNations,
  deleteNationById,
  addNation,
  updateNationById,
};
