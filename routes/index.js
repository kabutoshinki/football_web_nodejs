var express = require("express");
const Nations = require("../models/nations");
var router = express.Router();
var { getAllInfo, searchPlayers } = require("../controllers/home.js");

router.get("/", getAllInfo);
router.get("/search", searchPlayers);
module.exports = router;
