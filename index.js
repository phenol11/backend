const express = require("express");
const app = express();
const mongoose = require("mongoose");
const User = require("./models/user");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const validator = require("validator");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const generateToken = require("./utils/generateToken");

mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/store")
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Could not connect to MongoDB", err));

app.use(express.json());
app.use(cors());

const port = 3001;

app.get("/", (req, res) => {
  res.send("This is.........");
});

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!validator.isEmail(email) || !email.endsWith("@gmail.com")) {
      return res
        .status(400)
        .json({ error: "Invalid email! Please use a @gmail.com email." });
    }
    const newUser = new User({ email, password });
    await newUser.save();
    const token = generateToken(newUser);
    res.status(201).json({ message: "User registered successfully", token });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: "Email already registered" });
    }
    res.status(500).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      return res.status(400).json({ error: "Invalid email or password" });
    }
    const isMatch = await bcrypt.compare(password, existingUser.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }
    const token = generateToken(existingUser);
    res.status(200).json({ message: "Login successful!", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token)
    return res.status(401).json({ error: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: "Invalid token" });
  }
};

app.get("/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
