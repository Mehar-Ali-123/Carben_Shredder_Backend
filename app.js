import express from "express"; 
import ErrorHandlerMiddleware from "./middleware/error.js"; 
const app = express();
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import User from "./model/user.js";
import authRoutes from "./controller/auth.js"
import user from "./controller/user.js"

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));
app.use(cors());
app.use(express.json());
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Internal Server Error");
});
app.use(express.static("uploads"));

// Initialize and use session middleware
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport and use session middleware
app.use(express.urlencoded({ extended: true }));
app.use(
  session({ secret: "your-secret-key", resave: true, saveUninitialized: true })
);
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport Local Strategy
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async function (email, password, done) {
      try {
        const user = await User.findOne({ email });
        if (!user) {
          return done(null, false, { message: "Incorrect email." });
        }
        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
          return done(null, false, { message: "Incorrect password." });
        }
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    if (!user) {
      return done(null, false, { message: "User not found." });
    }
    return done(null, user);
  } catch (error) {
    return done(error);
  }
});

app.get("/", (req, res) => {
  res.send("API is working"); // Send a plain text response
});

app.use("/api/v2/user", user);


app.use("/api/auth", authRoutes);

app.use(ErrorHandlerMiddleware);
export default app;
