require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const app = express();

const port = process.env.PROT || 5000;

// middleware
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Quick cash server on running.....");
});
app.listen(port, () => {
  console.log(`Quick cash server on running on : ${port}`);
});
