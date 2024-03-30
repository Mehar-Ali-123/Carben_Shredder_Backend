const ErrorHandler = require("../utils/ErrorHandler.js");
const catchAsyncErrors = require("./catchAsyncError.js");
const jwt = require("jsonwebtoken");
const User = require("../model/user.js");

exports.isAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new ErrorHandler("Please login to continue", 401));
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);
    next();
  } catch (error) {
    return next(new ErrorHandler("Invalid or expired token", 401));
  }
});


// const jwt = require('jsonwebtoken');
// const ErrorHandler = require('../utils/ErrorHandler.js');
// const catchAsyncErrors = require('./catchAsyncError.js');
// const User = require('../model/user.js');

// exports.isAuthenticated = catchAsyncErrors(async (req, res, next) => {
//   const { token } = req.cookies;

//   if (!token) {
//     return next(new ErrorHandler('Please login to continue', 401));
//   }

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
//     req.user = await User.findById(decoded.id);
//     next();
//   } catch (error) {
//     return next(new ErrorHandler('Invalid token', 401));
//   }
// });
