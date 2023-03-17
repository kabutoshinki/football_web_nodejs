var createError = require("http-errors");
var express = require("express");
var cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
var logger = require("morgan");
const mongoose = require("mongoose");
var dotenv = require("dotenv");
var session = require("express-session");
var jwt = require("jsonwebtoken");
const cors = require("cors");
// router
var indexRouter = require("./routes/index");
var nationRouter = require("./routes/nationRouter");
var playerRouter = require("./routes/playerRouter");
var authRouter = require("./routes/auth");
var accountRouter = require("./routes/accounts");
var app = express();
dotenv.config();

mongoose.set("strictQuery", false);
// const url = "mongodb://127.0.0.1:27017/footballDB";
const url = "mongodb+srv://sdn:e1Gc6RA4FRM4iMI9@sdn.hkmti4p.mongodb.net/test";
const connect = mongoose.connect(url);

app.get("/", (req, res) => {
  const html = `
    <html>
      <head>
        <title>My Basic View</title>
      </head>
      <body>
        <h1>Welcome to my basic view!</h1>
        <p>This is some sample text.</p>
      </body>
    </html>
  `;
  res.send(html);
});

//middleware
// const addUserDataToLocals = (req, res, next) => {
//   if (req.cookies.user) {
//     const user = JSON.parse(req.cookies.user);
//     res.locals.user = user;
//   }
//   next();
// };
// const addUserDataToLocals = (req, res, next) => {
//   const token = req.cookies.access_token;
//   if (token) {
//     try {
//       const decoded = jwt.verify(token, process.env.JWT);
//       res.locals.user = decoded;
//     } catch (err) {
//       console.log(err);
//     }
//   }
//   next();
// };

app.use(cors());
app.use(logger("dev"));
app.use(cookieParser());
app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
// app.use(addUserDataToLocals);

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
  })
);

app.use("/api/v1/home", indexRouter);
app.use("/api/v1/nations", nationRouter);
app.use("/api/v1/players", playerRouter);
app.use("/api/v1/auth", authRouter);
app.use("/api/v1/users", accountRouter);
// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

// const url = "mongodb://127.0.0.1:27017/footballDB";

connect.then((db) => {
  console.log("connect successfully");
});

module.exports = app;
