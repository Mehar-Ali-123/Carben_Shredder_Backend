import express from "express";
import passport from "passport";
import User from "../model/user.js";
import sendToken from "../utils/jwtToken.js";

const router = express.Router();

// POST login route
router.post("/login", passport.authenticate("local"), async (req, res) => {
  try {
    const userId = req.user._id;

    const user = await User.findById(userId);

    if (!user) {
      throw new Error("User not found");
    }

    if (user.role !== "admin") {
      throw new Error("Unauthorized");
    }

    sendToken(user, 201, res);
    // res.json({ user: req.user, isAdmin: true, token: req.user.token });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: "Unauthorized Person" });
  }
});

router.post("/logout", (req, res) => {
  res.json({ message: "Logged out successfully." });
});

export default router;
