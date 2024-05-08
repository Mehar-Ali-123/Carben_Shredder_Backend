import express from "express";
import path from "path";
import upload from "../multer.js";
import User from "../model/user.js";
import Message from "../model/message.js";
import UserPlaid from "../model/userPlaid.js";
import ErrorHandler from "../utils/ErrorHandler.js";
import fs from "fs";
import jwt from "jsonwebtoken";
import sendMail from "../utils/sendMail.js";
import crypto from "crypto";
import catchAsyncError from "../middleware/catchAsyncError.js";
import sendToken from "../utils/jwtToken.js";
import bcrypt from "bcrypt";
import isAuthenticated from "../middleware/auth.js";
import { PlaidApi, Configuration, PlaidEnvironments } from "plaid";
import Stripe from "stripe";
const stripe = Stripe(
  "sk_test_51P9aNiGTvJh4FKHdrnQq53gSgK5YLisf8B2toyexH5uRBP4bBx6SEhikUY6KoNUWFQZBmWzCpK2lZR4OiFUXI2rd008oSLIUFa"
);
import { CNaughtApiClient } from "@cnaught/cnaught-node-sdk";
import dotenv from "dotenv";
dotenv.config({
  path: "../config/.env",
});

const router = express.Router();

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
// activation link
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

// Login User
router.post(
  "/login-user",
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
// check auth authenticated or not
router.get("/check-auth", isAuthenticated, (req, res) => {
  res.status(200).json({ isAuthenticated: true });
});

// Forget Pass
const otpMap = new Map();
router.post("/forgot-password", async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }

    const OTP = Math.floor(100000 + Math.random() * 900000);

    otpMap.set(email, OTP);

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

router.post("/reset-password", async (req, res, next) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }
    const storedOTP = otpMap.get(email);
    if (!storedOTP || storedOTP !== parseInt(otp, 10)) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    otpMap.delete(email);

    res
      .status(200)
      .json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res
      .status(500)
      .json({ success: false, message: "Error resetting password" });
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
  upload.single("file"),
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      const { name, email, country, currentPassword, newPassword } = req.body;
      const user = await User.findById(userId);
      if (!user) {
        return next(new ErrorHandler("User not found", 404));
      }

      user.name = name;
      user.email = email;
      user.country = country;

      if (req.file) {
        user.avatar = req.file.filename;
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

router.post("/logout", (req, res) => {
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

router.post("/contact", async (req, res) => {
  try {
    const { name, email, message } = req.body;

    const newMessage = new Message({
      senderName: name,
      senderEmail: email,
      messageBody: message,
    });

    await newMessage.save();

    res.status(201).json({ message: "Message sent successfully" });
  } catch (error) {
    console.error("Error handling contact form submission:", error);
    res.status(500).json({ error: "Failed to send message" });
  }
});
router.get("/contact-messages", async (req, res) => {
  try {
    const messages = await Message.find();
    res.status(200).json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// const CLIENT_ID = process.env.PLAID_CLIENT_ID;
// const SECRET = process.env.PLAID_SECRET_ID;
const CLIENT_ID = "65742c7d302cc7001c6c8bb1";
const SECRET = "20ff12e4635f7016f521de2e90a073";
const configuration = new Configuration({
  basePath: PlaidEnvironments.sandbox,
  baseOptions: {
    headers: {
      "PLAID-CLIENT-ID": CLIENT_ID,
      "PLAID-SECRET": SECRET,
    },
  },
});

const client = new PlaidApi(configuration);

router.post("/api/create-link-token", async function (req, res) {
  try {
    const { user } = req.body;
    const clientUserId = user._id;
    const plaidRequest = {
      user: {
        client_user_id: clientUserId,
      },
      client_name: "Plaid Test App",
      products: ["auth", "transactions"],
      language: "en",
      redirect_uri: "http://localhost:3000/",
      country_codes: ["US"],
    };
    const createTokenResponse = await client.linkTokenCreate(plaidRequest);
    const linkToken = createTokenResponse.data;
    res.status(200).json({ success: true, linkToken });
  } catch (error) {
    console.error("Error creating Plaid Link token:", error);
    res
      .status(500)
      .json({ success: false, error: "Error creating Plaid Link token" });
  }
});

router.post("/plaid/exchange-token", async (req, res) => {
  try {
    const { publicToken } = req.body;

    const exchangeTokenResponse = await client.itemPublicTokenExchange({
      public_token: publicToken,
    });

    const { access_token, item_id } = exchangeTokenResponse.data;

    // Save the access token and item ID to your database
    // Example: Save to MongoDB
    // const plaidData = new User({
    //   userId: req.user.id,
    //   accessToken: access_token,
    //   itemId: item_id,
    // });
    // await plaidData.save();

    res.status(200).json({
      success: true,
      accessToken: access_token,
      itemId: item_id,
    });
  } catch (error) {
    console.error("Error exchanging Plaid public token:", error);
    res
      .status(500)
      .json({ success: false, error: "Error exchanging Plaid public token" });
  }
});

router.post("/plaid/retrieve-accounts", async (req, res) => {
  try {
    const { accessToken } = req.body;

    const accountsResponse = await client.accountsGet({
      access_token: accessToken,
    });

    const { accounts } = accountsResponse.data;

    // const userPlaid = new UserPlaid({
    //   plaidData: {
    //     accessToken,
    //     accounts,
    //   },
    // });

    // await userPlaid.save();
    res.status(200).json({
      success: true,
      accountsData: accounts,
    });
  } catch (error) {
    console.error("Error retrieving accounts data:", error);
    res
      .status(500)
      .json({ success: false, error: "Error retrieving accounts data" });
  }
});

router.post("/plaid/auth", async (req, res) => {
  try {
    const { accessToken, name, email } = req.body;
    const plaidAuthRequest = {
      access_token: accessToken,
    };
    const plaidResponse = await client.authGet(plaidAuthRequest);

    const userPlaid = new UserPlaid({
      name,
      email,
      plaidData: {
        accessToken,
        authData: plaidResponse.data,
      },
    });

    await userPlaid.save();
    res.json(plaidResponse.data);
  } catch (error) {
    console.error("Error fetching Plaid authentication data:", error);
    res.status(500).send("Authentication failed");
  }
});

router.post("/transactions/get", async (req, res) => {
  try {
    const { accessToken } = req.body;
    if (!accessToken) {
      return res
        .status(400)
        .json({ success: false, error: "Access token is required" });
    }
    const request = {
      access_token: accessToken,
      start_date: "2018-01-01",
      end_date: "2024-04-01",
    };
    const response = await client.transactionsGet(request);
    const transactions = response.data.transactions;

    await UserPlaid.updateOne(
      { "plaidData.accessToken": accessToken },
      { $set: { "plaidData.transactions": transactions } }
    );

    res.status(200).json({ success: true, transactions });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res
      .status(500)
      .json({ success: false, error: "Error fetching transactions" });
  }
});

router.get("/plaid/all-data", async (req, res) => {
  try {
    // Fetch all UserPlaid documents from the database
    const userPlaids = await UserPlaid.find();

    res.status(200).json({ success: true, plaidData: userPlaids });
  } catch (error) {
    console.error("Error fetching Plaid data:", error);
    res
      .status(500)
      .json({ success: false, error: "Error fetching Plaid data" });
  }
});
 
// STRIPE API SETUP
router.post("/create-checkout-session", isAuthenticated, async (req, res) => {
  try {
    const { payAmount, productName, productDescription } = req.body;
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: productName,
              description: productDescription,
            },
            unit_amount: payAmount * 100,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: "http://localhost:3000/success-payment",
      cancel_url: "http://localhost:3000/subcription-plan",
    });

    if (!session || !session.id) {
      throw new Error("Failed to create checkout session");
    } 
    res.json({ sessionId: session.id });
  } catch (error) {
    console.error("Error creating checkout session:", error);
    res.status(500).json({ error: error.message });
  }
});
router.get("/session_status/:session_id", async (req, res) => {
  try {
    const { session_id } = req.params;
    const session = await stripe.checkout.sessions.retrieve(session_id);

    const customerEmail = session.customer_details
      ? session.customer_details.email
      : null;

    if (customerEmail !== null) { 
    } else {
      console.error("Customer email is null or undefined.");
    }

    res.status(200).json({
      status: session.status,
      payment_status: session.payment_status,
      customer_email: customerEmail,
    });
  } catch (error) {
    console.error("Error retrieving session:", error);
    res.status(500).json({ error: "Failed to retrieve session" });
  }
});



// Cnught api starts here
const apiKey = "C0-sandbox-bxXNdnUfQIu0BJqUw1nDUiVay8UdmI5F6";
const clientCnaught = new CNaughtApiClient(apiKey);
router.post("/create-cnaught-subaccount", isAuthenticated, async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!name) {
      throw new Error("Name is required");
    }

    const userId = req.user.id;

    const existingUser = await User.findById(userId);
    if (!existingUser) {
      throw new Error("User not found");
    }

    if (existingUser.cnughtCreatedSubaccunt.length > 0) {
      return res.status(400).json({ error: "User already has a subaccount" });
    }

    const subaccount = await clientCnaught.createSubaccount({ name, email });

    await User.findByIdAndUpdate(userId, {
      $push: {
        cnughtCreatedSubaccunt: {
          subaccountId: subaccount.id,
          name: subaccount.name,
          email: subaccount.email,
        },
      },
    });

    res.json(subaccount);
  } catch (error) {
    console.error("Error creating subaccount:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});
router.post("/create-cnaught-order", isAuthenticated, async (req, res) => {
  try {
    const { amount_kg, subaccountId } = req.body;
    const userId = req.user.id;

    const existingUser = await User.findById(userId);
    if (!existingUser) {
      throw new Error("User not found");
    }

    const order = await clientCnaught.placeGenericOrder({
      amount_kg,
      subaccountId,
    });
    await User.findByIdAndUpdate(userId, {
      $push: {
        cnughtCreatedOrder: {
          order_number: order.order_number,
          amount_kg: order.amount_kg,
          price_usd_cents: order.price_usd_cents,
          created_on: order.created_on,
          state: order.state,
        },
      },
    });
    res.status(201).json({ success: true, order });
  } catch (error) { 
    res.status(500).json({
      success: false,
      error: "An error occurred while creating the order",
    });
  }
});
router.get("/cnaught-order/:orderId", async (req, res) => {
  const orderId = req.params.orderId;

  try {
    const orderDetails = await clientCnaught.getOrderDetails(orderId);
    res.json(orderDetails);
  } catch (error) {
    console.error("Error fetching order details:", error);
    res.status(500).json({ error: "Failed to fetch order details" });
  }
});

export default router;
