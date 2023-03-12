var express = require("express");
var uploadCloud = require("../utils/uploader.js");
var {
  getAllPlayers,
  getPlayerById,
  deletePlayerById,
  createPlayer,
  updatePlayer,
} = require("../controllers/players.js");
var { verifyUser, verifyAdmin } = require("../utils/verifyToken");
let router = express.Router();

router.get("/", getAllPlayers);
router.post("/", uploadCloud.single("image"), createPlayer);
router.get("/:id", getPlayerById);
router.put("/update", uploadCloud.single("image"), updatePlayer);
router.delete("/delete/:id", deletePlayerById);
module.exports = router;
