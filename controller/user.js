const express = require("express");
const path = require("path");
const { upload } = require("../multer");
const User = require("../model/user.js");
const ErrorHandler = require("../utils/ErrorHandler");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const sendMail = require("../utils/sendMail.js");
const router = express.Router();
const crypto = require("crypto");
const catchAsyncError = require("../middleware/catchAsyncError.js");
const sendToken = require("../utils/jwtToken.js");
const bcrypt = require("bcrypt");
const { isAuthenticated } = require("../middleware/auth.js");

router.post("/create-user", upload.single("file"), async (req, res, next) => {
  try {
    const { name, email, password , country } = req.body;

    // Check if the email is not null
    if (!email) {
      return next(new ErrorHandler("Email cannot be null", 400));
    }

    // Check if the email already exists
    const existingUser = await User.findOne({ email }).maxTimeMS(30000);
    if (existingUser) {
      // Remove uploaded file if user already exists
      const filename = req.file.filename;
      const filePath = path.join(__dirname, "..", "uploads", filename);
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error("Error deleting file:", err);
        }
      });
      return next(new ErrorHandler("User email already exists", 400));
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user document with hashed password
    const newUser = new User({
      name,
      email,
      country,
      password: hashedPassword,
      avatar: req.file.filename,
    });

    await newUser.save();

    console.log("User created successfully:", newUser);

    const activationToken = createActivationToken(newUser);
    const activationUrl = `http://localhost:5173/activation/${activationToken}`;

    try {
      await sendMail({
        email: newUser.email,
        subject: "Activate your email",
        message: `Hello ${newUser.name}, please click on the link to activate your account: ${activationUrl}`,
      });
      res.status(201).json({
        success: true,
        message: `Please check your email ${newUser.email} to activate your account`,
      });
    } catch (error) {
      return next(new ErrorHandler("Error sending activation email", 500));
    }
  } catch (error) {
    console.error("Error creating user:", error);
    next(error);
  }
});

// Function to create activation token
const createActivationToken = (newUser) => {
  const payload = {
    userId: newUser._id,
  };
  return jwt.sign(payload, process.env.ACTIVATION_SECRET, {
    expiresIn: "5m",
  });
};

router.post(
  "/activation",
  catchAsyncError(async (req, res, next) => {
    try {
      const { activatio_token } = req.body;
      const newUser = jwt.verify(
        activatio_token,
        process.env.ACTIVATION_SECRET
      );
      if (!newUser) {
        return next(new ErrorHandler("invalid token ", 400));
      }
      let user = User.findOne({ email });
      if (user) {
        return next(new ErrorHandler("User already exist", 400));
      }
      const { name, email, password, avatar } = newUser;
      // Hash the password before creating the user
      const hashedPassword = await bcrypt.hash(password, 10); // 10 is the number of salt rounds
      user = User.create({
        name,
        email,
        password: hashedPassword,
        avatar,
      });
      sendToken(user, 201, res);
    } catch (error) {}
  })
);

router.post(
  "/login-user",
  catchAsyncError(async (req, res, next) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return next(new ErrorHandler("Please provide email and password", 400));
      }
      const user = await User.findOne({ email }).select("+password");
      console.log("User retrieved from MongoDB:", user); // Add this line to log the user object
      if (!user) {
        return next(new ErrorHandler("User does not exist", 400));
      }
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return next(new ErrorHandler("Incorrect password", 400));
      }

      res.cookie("userID", user._id, { maxAge: 900000, httpOnly: true });

      // Send token in response
      sendToken(user, 201, res);
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// load router

router.get(
  "/get-user",
  isAuthenticated,
  catchAsyncError(async (req, res, next) => {
    try {
      const user = User.findById(req.user.id);
      if (!user) {
        return next(new ErrorHandler("user does not exist ", 400));
      }
      res.status(200).json({
        success: true,
        user,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

module.exports = router;
