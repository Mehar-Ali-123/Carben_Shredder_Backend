const express = require("express");
const ErrorHandler = require("./middleware/error");
const app = express();
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const cors = require("cors");

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));
// const corsOptions = {
//   origin: "https://busy-jade-cobra-toga.cyclic.app/",
// };
// app.use(cors(corsOptions));
app.use(cors());

// app.use("/", express.static("uploads"));
app.use(express.json());
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Internal Server Error");
});

app.use(express.static("./uploads"));

// config
// if (process.env.NODE_ENV !== "PRODUCTION") {
//   require("dotenv").config({
//     path: "./config/.env",
//   });
// }
// Root API endpoint
app.get("/", (req, res) => {
  res.send("API is working"); // Send a plain text response
});

const user = require("./controller/user");
app.use("/api/v2/user", user);
app.use(ErrorHandler);
module.exports = app;
