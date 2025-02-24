require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const app = express();

const port = process.env.PROT || 5000;

// middleware
app.use(cors());
app.use(express.json());

// db connection
async function main() {
  try {
    await mongoose.connect(process.env.DB_URI);
    console.log("MongoDB connected");
  } catch (err) {
    console.log(err);
  }
}
main();

// Schema
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    hashedPin: { type: String, required: true, length: 5 },
    mobileNumber: { type: String, required: true, unique: true }, //Unique
    email: {
      type: String,
      required: true,
      unique: true,
      match: /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/, //validate, Unique
    },
    nid: { type: String, require: true, unique: true }, //Unique
    role: { type: String, enum: ["user", "agent", "admin"], default: "user" },
  },
  { timestamps: true }
);
// Model
const Users = mongoose.model("Users", userSchema);

// JWT TOKEN Generate
const tokenGenerate = (user) => {
  const privateKey = process.env.PRIVATE_KEY;
  const payload = { userId: user._id, name: user.name, role: user.role };
  const token = jwt.sign(payload, privateKey, { expiresIn: "30min" });
  return token;
};

// users related apis
app.post("/log-in", async (req, res) => {
  try {
    const { mobileNumber, email, pin } = req.body;
    // Check if any field is missing
    if (!pin) {
      return res.status(400).json({ message: "All fields are required" });
    }
    // check user email
    let user;
    if (email) {
      user = await Users.findOne({ email });
    }
    if (mobileNumber) {
      user = await Users.findOne({ mobileNumber });
    }
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // compare pin
    const isMatch = await bcrypt.compare(pin, user.hashedPin);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // JWT Token Provide
    const token = tokenGenerate(user);
    res.status(200).json({
      message: "Login successful",
      token: token,
    });
  } catch (error) {}
});

app.post("/register", async (req, res) => {
  try {
    const { name, pin, email, nid, mobileNumber, role } = req.body;

    // Check if any field is missing
    if (!name || !pin || !email || !nid || !mobileNumber || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // password hash
    const saltRounds = +process.env.PASS_BCRYPT;
    const hashedPin = await bcrypt.hash(pin, saltRounds);

    // user data
    const user = {
      name,
      hashedPin,
      email,
      mobileNumber,
      nid,
      role,
    };
    // save to db
    const result = await Users.insertOne(user);
    console.log(result);
    // token
    const token = tokenGenerate(result);
    res.status(201).json({ message: "User registered successfully", token });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
    console.log("RegisterErr", error);
  }
});

app.get("/", (req, res) => {
  res.send("Quick cash server on running.....");
});
app.listen(port, () => {
  console.log(`Quick cash server on running on : ${port}`);
});
