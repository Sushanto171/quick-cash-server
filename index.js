require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const app = express();

const port = process.env.PROT || 5000;

// middleware
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
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

// Verify token
const verifyToken = async (req, res, next) => {
  try {
    // Get the token
    const token = req?.headers["authorization"]?.split(" ")[1];

    // Check token
    if (!token) {
      return res
        .status(403)
        .json({ message: "Forbidden: unauthorized access" });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.PRIVATE_KEY);

    req.user = decoded;

    next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({ message: "unAuthorized access" });
  }
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

    const userData = {
      name: user.name,
      role: user.role,
      email: user.email,
      mobileNumber: user.mobileNumber,
    };
    // JWT Token Provide
    const token = tokenGenerate(user);
    res.status(200).json({
      message: "Login successful",
      token: token,
      data: userData,
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
    // check user
    let isExist;
    let message;
    if (email || mobileNumber) {
      if (email) {
        isExist = await Users.findOne({ email });
        if (isExist) message = "Email already save to database";
      }
      if (mobileNumber) {
        isExist = await Users.findOne({ mobileNumber });
        if (isExist) message = "Number already save to database";
      }
      if (nid) {
        isExist = await Users.findOne({ nid });
        if (isExist) message = "NID already save to database";
      }
    }
    if (isExist) {
      return res.status(200).json({ message });
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

    const userData = {
      name: user.name,
      role: user.role,
      email: user.email,
      mobileNumber: user.mobileNumber,
    };
    // token
    const token = tokenGenerate(result);
    res
      .status(201)
      .json({ message: "User registered successfully", token, data: userData });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
    console.log("RegisterErr", error);
  }
});

app.get("/role/:email", verifyToken, async (req, res) => {
  try {
    // console.log(req.user);
    const email = req.params.email;
    const result = await Users.findOne({ email });
    const role = result.role;

    res.json({ role });
  } catch (error) {
    console.log("role", error);
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.get("/", (req, res) => {
  res.send("Quick cash server on running.....");
});
app.listen(port, () => {
  console.log(`Quick cash server on running on : ${port}`);
});
