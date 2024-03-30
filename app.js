const express = require("express");
const ErrorHandler = require("./middleware/error");
const app = express();
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const cors = require("cors");

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));
// Allow requests from all origins with credentials
app.use(
  cors({
    // origin: "https://carbon-shredder-backend.vercel.app",
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use("/", express.static("uploads"));
app.use(express.json());
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Internal Server Error");
});

// config
// if (process.env.NODE_ENV !== "PRODUCTION") {
//   require("dotenv").config({
//     path: "./config/.env",
//   });
// }

const user = require("./controller/user");
app.use("/api/v2/user", user);
app.use(ErrorHandler);
module.exports = app;
