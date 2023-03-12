const { default: mongoose } = require("mongoose");
const Player = require("../models/players");
const Nations = require("../models/nations");
// const getAllInfo = async (req, res) => {
//   try {
//     var perPage = 3;
//     var total = await Player.find().count();
//     var pages = Math.ceil(total / perPage);
//     var pageNumber = req.query.page == null ? 1 : req.query.page;
//     var startFrom = (pageNumber - 1) * perPage;
//     var players = await Player.find({ isCaptain: true }).populate("nation").skip(startFrom).limit(perPage);

//     res.render("home", { players: players, pages: pages, title: "Home Page" });
//   } catch (err) {
//     res.status(500).json(err);
//   }
// };

const getAllInfo = async (req, res) => {
  try {
    var perPage = 3;
    var total = await Player.find().count();
    var pages = Math.ceil(total / perPage);
    var pageNumber = req.query.page == null ? 1 : req.query.page;
    var startFrom = (pageNumber - 1) * perPage;
    var pageNum = await Player.find().populate("nation").count();
    var players = await Player.find().populate("nation").skip(startFrom).limit(perPage);
    res.header("Access-Control-Allow-Origin", "*");
    res.status(200).json({ players, pageNum });
  } catch (err) {
    res.status(500).json(err);
  }
};

const searchPlayers = async (req, res) => {
  try {
    const searchQuery = new RegExp(req.query.search, "i"); // case-insensitive search
    const perPage = 3;
    const total = await Player.find({ name: searchQuery }).countDocuments();
    console.log(total);
    const pages = Math.ceil(total / perPage);
    const pageNumber = req.query.page == null ? 1 : req.query.page;
    const startFrom = (pageNumber - 1) * perPage;

    const listPlayer = await Player.find({ name: searchQuery }).populate("nation").skip(startFrom).limit(perPage);

    // Return JSON data instead of rendering a view
    res.status(200).json({
      list: listPlayer,
      title: "Search Page",
      searchQuery: req.query.search,
      pages: pages,
      total: total,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error });
  }
};

module.exports = {
  getAllInfo,
  searchPlayers,
};
