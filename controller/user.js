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
    const { name, email, password, country, signupDate } = req.body;
    if (!email) {
      return next(new ErrorHandler("Email cannot be null", 400));
    } 
    const existingUser = await User.findOne({ email }).maxTimeMS(30000);
    if (existingUser) {
      const filename = req.file.filename;
      const filePath = path.join(__dirname, "..", "uploads", filename);
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error("Error deleting file:", err);
        }
      });
      return next(new ErrorHandler("User email already exists", 400));
    }

    const hashedPassword = await bcrypt.hash(password, 10); 
    const emailToken = crypto.randomBytes(64).toString("hex");


    const newUser = new User({
      name,
      email,
      country,
      password: hashedPassword,
      avatar: req.file.filename,
      signupDate,
      emailToken,
      isVerified: false,
    });

    await newUser.save(); 
    // const activationToken = createActivationToken(newUser);
    const activationUrl = `http://localhost:3000/activation/${emailToken}`;

    try {
      await sendMail({
        email: newUser.email,
        subject: "Activate your email",
        message: `Hello ${newUser.name}, Best Wishes From Carbon Shredder ,  please click on the link to activate your account:
         ${activationUrl}`,
      });
      res.status(201).json({
        success: true,
        message: `Please check your email ${newUser.email} to activate your account`,
      });
    } catch (error) {
      return next(new ErrorHandler("Error sending activation email", 500));
    }

    console.log("User created successfully:", newUser);
  } catch (error) {
    console.error("Error creating user:", error);
    next(error);
  }
});

const createActivationToken = (user) => {
  return jwt.sign(
    {
      userId: user._id,
    },
    process.env.ACTIVATION_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES,
    }
  );
};

router.post("/activation", async (req, res, next) => {
  try {
    const { activationToken } = req.body;
    console.log("Received activation token:", activationToken);
    if (!activationToken) {
      return next(new ErrorHandler("Activation token is required", 400));
    }
    const user = await User.findOne({ emailToken: activationToken });
    if (user) {
      console.log("Found user:", user);
      user.emailToken = null;
      user.isVerified = true;
      await user.save();
      return res
        .status(200)
        .json({ success: true, message: "Account activated successfully" });
    } else {
      console.log("Invalid activation token");
      return next(new ErrorHandler("Invalid activation token", 400));
    }
  } catch (error) {
    console.error("Error in activation endpoint:", error); // Add this line for debugging
    return next(new ErrorHandler(error.message, 500));
  }
});

router.post( "/login-user",
  catchAsyncError(async (req, res, next) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return next(new ErrorHandler("Please provide email and password", 400));
      }
      const user = await User.findOne({ email }).select("+password");
      console.log("User retrieved from MongoDB:", user);  
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
router.get("/check-auth", isAuthenticated, (req, res) => { 
  res.status(200).json({ isAuthenticated:true });
});
 

// forgot password 
const otpMap = new Map(); // Create a Map to store OTPs temporarily

router.post("/forgot-password", async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const OTP = Math.floor(100000 + Math.random() * 900000);

    otpMap.set(email, OTP); // Store the OTP temporarily

    try {
      await sendMail({
        email: email,
        subject: "Reset Your Password",
        message: `Carbon Shredderr , Your OTP for password reset is: ${OTP}`,
      });
      res.status(201).json({
        success: true,
        message: `Please check your email ${email} for the OTP to reset your password`,
      });
    } catch (error) {
      return next(new ErrorHandler("Error sending OTP", 500));
    }
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ success: false, message: "Error sending OTP" });
  }
});

// reset password  

router.post("/reset-password", async (req, res, next) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    } 
    const storedOTP = otpMap.get(email);
    if (!storedOTP || storedOTP !== parseInt(otp, 10)) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    } 
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    } 

    // Hash the new password before saving
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save(); 
    otpMap.delete(email);

    res.status(200).json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ success: false, message: "Error resetting password" });
  }
});



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

router.get(
  "/get-profile-data",
  isAuthenticated,
  catchAsyncError(async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        return next(new ErrorHandler("User not found", 404));
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

router.put(
  "/update-profile",
  isAuthenticated,
  upload.single("file"), // 'file' is the field name for the image in the form
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      const { name, email, country, currentPassword, newPassword } = req.body;

      // Check if the user exists
      const user = await User.findById(userId);
      if (!user) {
        return next(new ErrorHandler("User not found", 404));
      }

      user.name = name;
      user.email = email;
      user.country = country;

      if (req.file) {
        user.avatar = req.file.filename; // Update the avatar field with the uploaded file's filename
      }

      const isPasswordMatch = await bcrypt.compare(
        currentPassword,
        user.password
      );
      if (!isPasswordMatch) {
        return next(new ErrorHandler("Incorrect current password", 400));
      }

      if (newPassword) {
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedNewPassword;
      }

      await user.save();

      res.status(200).json({
        success: true,
        message: "User profile and password updated successfully",
        user,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  }
);

router.post("/grant-admin-role", async (req, res) => {
  try {
    const { email } = req.body;

    const userToUpdate = await User.findOne({ email });

    if (!userToUpdate) {
      throw new Error("User not found.");
    }

    userToUpdate.role = "admin";
    await userToUpdate.save();

    res.json({ message: "Admin role granted successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

router.post("/logout",  (req, res) => { 
  // res.cookie("userID", "", { maxAge: 0, httpOnly: true });
  res.json({ isAuthenticated: false, message: "Logged out successfully." });
});

router.post("/subscription-details", async (req, res, next) => {
  try {
    const { subscriptionType, email, name } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    user.subscriptionType = subscriptionType;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Subscription details updated successfully",
      user,
    });
  } catch (error) {
    return next(new ErrorHandler(error.message, 500));
  }
});

router.get("/get-users-data", isAuthenticated, async (req, res, next) => {
  try {
    const users = await User.find().select(
      "name email subscriptionType country avatar signupDate"
    );

    if (!users || users.length === 0) {
      return res.status(404).json({
        success: false,
        error: "No users found",
      });
    }

    res.status(200).json({
      success: true,
      users,
    });
  } catch (error) {
    return next(new ErrorHandler(error.message, 500));
  }
});

router.put("/update-user/:userId", isAuthenticated, async (req, res, next) => {
  try {
    const { subscriptionType, country, profilePic, email, name } = req.body;
    const userId = req.params.userId;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Update all fields regardless of whether they are provided or not
    user.subscriptionType = subscriptionType || user.subscriptionType;
    user.country = country || user.country;
    user.profilePic = profilePic || user.profilePic;
    user.email = email || user.email;
    user.name = name || user.name;

    await user.save();

    res.status(200).json({
      success: true,
      message: "User data updated successfully",
      user,
    });
  } catch (error) {
    return next(new ErrorHandler(error.message, 500));
  }
});

router.delete(
  "/delete-user/:userId",
  isAuthenticated,
  async (req, res, next) => {
    try {
      const userId = req.params.userId;

      // Find the user by ID and delete
      const deletedUser = await User.findByIdAndDelete(userId);

      if (!deletedUser) {
        return res.status(404).json({
          success: false,
          error: "User not found",
        });
      }

      res.status(200).json({
        success: true,
        message: "User deleted successfully",
        deletedUser,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  }
);



module.exports = router;
