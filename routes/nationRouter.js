var express = require("express");
const bodyParser = require("body-parser");
var uploadCloud = require("../utils/uploader.js");

var { getAllNations, deleteNationById, addNation, updateNationById } = require("../controllers/nations.js");
var { verifyUser, verifyAdmin } = require("../utils/verifyToken");

let router = express.Router();

router.get("/", getAllNations);
router.post("/", uploadCloud.single("image"), addNation);
router.post("/update/", uploadCloud.single("image"), updateNationById);
router.delete("/delete/:id", deleteNationById);

module.exports = router;
