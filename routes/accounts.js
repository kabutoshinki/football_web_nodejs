var express = require("express");
var router = express.Router();
var { getAllUser } = require("../controllers/users");
var { verifyUser, verifyAdmin } = require("../utils/verifyToken");
/* GET users listing. */
router.get("/", getAllUser);

module.exports = router;
