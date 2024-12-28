import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import colors from "colors";
import connectDB from "./config/connectDB.js";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "./models/auth.js";

dotenv.config();
connectDB();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

const app = express();
app.use(express.json({ limit: "300mb", extended: true }));
app.use(express.urlencoded({ limit: "300mb", extended: true }));
app.use(cors());
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.send("This is an API by Rajat Petkar");
});


app.post("/signup", async (req, res) => {
  const { name, email, password , api } = req.body;

  if (!name || !email || !password || !api) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists." });
    }

 
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      api
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  try {

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials." });
    }


    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials." });
    }


    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });

    console.log(user.api)
   
    res.json({
      message: "Login successful",
      token,
      api: user.api,
      name: user.name,
      email: user.email
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

app.put("/edit-api", async (req, res) => {
  const { userId, newApiKey } = req.body;

  if (!userId || !newApiKey) {
    return res.status(400).json({ message: "User ID and API key are required." });
  }

  try {
    
    const user = await User.findByIdAndUpdate(userId, { api: newApiKey }, { new: true });

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    res.json({ message: "API key updated successfully.", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`.bgBlue.white);
});
