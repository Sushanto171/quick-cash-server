require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const app = express();
const { Server } = require("socket.io");
const { createServer } = require("node:http");
const server = createServer(app);
const io = new Server(server);
const port = process.env.PROT || 5000;

// middleware
const corsOptions = {
  origin: ["*"],
  methods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
  credentials: true,
};

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

// Apply CORS Middleware
app.use(cors(corsOptions));

app.use(express.json());
app.use(bodyParser.json());
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
    amount: { type: Number, default: 0 },
    status: { type: Boolean, default: false }, //if admin action block
    approve: { type: Boolean, default: false }, // agent approval
    deviceId: { type: String },
  },
  { timestamps: true }
);

// admin transaction
const adminTransactionSchema = new mongoose.Schema({
  totalTransactions: {
    type: Number,
    default: 0, // Total number of transactions
  },
  totalAmountProcessed: {
    type: Number,
    default: 0, // Total amount processed in all transactions
  },
  totalSendMoneyFees: {
    type: Number,
    default: 0, // Total collected fees from transactions
  },
  lastUpdated: {
    type: Date,
    default: Date.now, // Track last update time
  },
});
//model adminTransaction
const AdminTransaction = mongoose.model(
  "AdminTransaction",
  adminTransactionSchema
);

// agent schema
const agentTransactionSchema = new mongoose.Schema({
  agentMobileNumber: {
    type: String,
    required: true,
    unique: true,
  },
  name: {
    type: String,
  },
  totalTransactions: {
    type: Number,
    default: 0,
  },
  totalAmountProcessed: {
    type: Number,
    default: 0,
  },
  totalCommissionEarned: {
    type: Number,
    default: 0,
  },
  totalCashIn: {
    type: Number,
    default: 0,
  },
  totalCashOut: {
    type: Number,
    default: 0,
  },
  lastUpdated: {
    type: Date,
    default: Date.now,
  },
});
// model
const AgentTransaction = mongoose.model(
  "AgentTransaction",
  agentTransactionSchema
);

// transaction schema
const transactionSchema = new mongoose.Schema({
  accountType: {
    type: String,
    required: true,
  },
  finalAmount: {
    type: Number,
    required: true,
  },
  mobileNumber: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  receiverAccountType: {
    type: String,
    required: true,
  },
  receiverMobileNumber: {
    type: String,
    required: true,
  },
  receiverName: {
    type: String,
    required: true,
  },
  sendMoneyFee: {
    type: Number,
  },
  status: {
    type: String,
    enum: ["unsent", "sent", "failed"], // Only allow these statuses
    default: "unsent",
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  totalAmount: {
    type: Number,
    required: true,
  },
  transaction: {
    type: String,
    unique: true,
    required: true,
  },
});
// model
const Transaction = mongoose.model("transaction", transactionSchema);

// Model
const Users = mongoose.model("Users", userSchema);

// JWT TOKEN Generate
const tokenGenerate = (user) => {
  const privateKey = process.env.PRIVATE_KEY;
  const payload = {
    userId: user._id,
    name: user.name,
    role: user.role,
    email: user.email,
  };
  const token = jwt.sign(payload, privateKey, { expiresIn: "7d" });
  return token;
};

// Verify token
const verifyToken = async (req, res, next) => {
  try {
    // Get the token
    const token = req?.headers["authorization"]?.split(" ")[1];
    const deviceId = req?.headers["x-device-id"]; // come to client side
    // Check token
    if (!token) {
      return res
        .status(403)
        .json({ message: "Forbidden: unauthorized access" });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.PRIVATE_KEY);

    const user = await Users.findOne({ email: decoded.email });
    if (user.deviceId == !deviceId) {
      return res
        .status(401)
        .json({ message: "Logged in from another device!" });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({ message: "unAuthorized access" });
  }
};

const verifyPin = async (pin, email = null, mobileNumber = null) => {
  // check user email

  let user;
  if (email) {
    user = await Users.findOne({ email });
  }
  if (mobileNumber) {
    user = await Users.findOne({ mobileNumber });
  }
  if (!user) {
    return false;
  }
  // compare pin
  const isMatch = await bcrypt.compare(pin, user.hashedPin);

  if (!isMatch) {
    return null;
  }
  return user;
};

//
const verifyAdmin = async (req, res, next) => {
  try {
    const { email } = req.user;

    const result = await Users.findOne({ email });
    const role = result?.role === "admin";
    if (!role) {
      return res
        .status(403)
        .json({ message: "Forbidden: unAuthorized access" });
    }

    next();
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
};
// auth related apis
app.post("/log-in", async (req, res) => {
  try {
    const { mobileNumber, email, pin, deviceId } = req.body;
    // Check if any field is missing
    if (!pin) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // compare pin
    const user = await verifyPin(pin, email, mobileNumber);
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // save device  id
    await Users.updateOne(
      { email: user.email },
      { $set: { deviceId: deviceId } }
    );
    const userData = {
      name: user.name,
      role: user.role,
      email: user.email,
      mobileNumber: user.mobileNumber,
      amount: user?.amount,
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

    // Check if email, mobile, or nid already exist
    let isExist = await Users.findOne({
      $or: [{ email }, { mobileNumber }, { nid }],
    });

    if (isExist) {
      let message;
      if (isExist.email === email) message = "Email already save to database";
      if (isExist.mobileNumber === mobileNumber)
        message = "Number already save to database";
      if (isExist.nid === nid) message = "NID already save to database";
      return res.status(200).json({ message });
    }

    // Password hash
    const saltRounds = +process.env.PASS_BCRYPT || 10; // Fallback to 10 if not set
    const hashedPin = await bcrypt.hash(pin, saltRounds);

    // User data
    const user = { name, hashedPin, email, mobileNumber, nid, role };
    const result = await Users.insertOne(user);

    // Bonus allocation for users
    let bonus = 0;
    if (result?._id && result.role === "user") {
      bonus = 40;
      await Users.updateOne(
        { email: result.email },
        { $set: { amount: bonus } }
      );
    }

    // update admin fund
    await AdminTransaction.updateOne(
      {},
      { $inc: { totalAmountProcessed: 20 } }
    );

    const userData = {
      name: user.name,
      role: user.role,
      email: user.email,
      mobileNumber: user.mobileNumber,
      amount: bonus,
    };

    // Generate token
    const token = tokenGenerate(result);

    res.status(201).json({
      message: "User registered successfully",
      token,
      data: userData,
      bonus,
    });
  } catch (error) {
    console.error("RegisterErr", error);
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

//
app.get("/auth/me", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ email: decoded.email });

    if (!user || user.token !== token) {
      return res
        .status(401)
        .json({ error: "Invalid token or logged in from another device" });
    }

    res.json({ user: { email: user.email } });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// users related apis
// get all users
app.get("/users", verifyToken, async (req, res) => {
  try {
    const result = await Users.aggregate([
      {
        $project: {
          _id: 1,
          name: 1,
          email: 1,
          role: 1,
          mobileNumber: 1,
          amount: 1,
          status: 1,
          approve: 1,
        },
      },
    ]);
    res.status(200).json({
      message: "Fetching all user data successfully",
      data: result,
    });
  } catch (error) {
    console.log("role", error);
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// get-user amount
app.get("/user-amount/:email", verifyToken, async (req, res) => {
  try {
    const user = req.user;
    const email = req.params.email;
    if (email !== user.email) {
      return res
        .status(403)
        .json({ message: "Forbidden: unAuthorized access" });
    }

    const result = await Users.findOne({ email });
    if (result) {
      const amount = result.amount;
      res.status(200).json({ message: "get user amount", amount });
    }
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// get user role
app.get("/role/:email", verifyToken, async (req, res) => {
  try {
    const user = req.user;
    const email = req.params.email;
    if (email !== user.email) {
      return res
        .status(403)
        .json({ message: "Forbidden: unAuthorized access" });
    }
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

//user block by admin
app.patch("/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const updatedUser = await Users.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ message: "User status updated", updatedUser });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

//user search
app.get("/users/search?", async (req, res) => {
  try {
    const { query: mobileNumber } = req.query;
    console.log(mobileNumber);
    if (!mobileNumber) {
      return res.status(400).json({ message: "Mobile number is required" });
    }

    const user = await Users.find({
      mobileNumber: { $regex: new RegExp(mobileNumber, "i") },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// get user by transaction by user mobile number
app.get("/user-transaction/:mobileNumber?", verifyToken, async (req, res) => {
  try {
    const { mobileNumber } = req.params;
    const { limit } = req.query;

    const transactions = await Transaction.find({
      $or: [
        {
          senderMobileNumber: {
            $regex: new RegExp(`^${mobileNumber}$`, "i"),
          },
        },
        {
          mobileNumber: { $regex: new RegExp(`^${mobileNumber}$`, "i") },
        },
        {
          receiverMobileNumber: {
            $regex: new RegExp(`^${mobileNumber}$`, "i"),
          },
        },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(limit === "100" ? 100 : "");

    res.status(200).json({ transactions });
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
      error: error.message,
    });
  }
});

// send mane user
app.post("/send-maney/:email", verifyToken, async (req, res) => {
  try {
    const user = req.user;
    const email = req.params.email;
    if (email !== user.email) {
      return res
        .status(403)
        .json({ message: "Forbidden: unAuthorized access" });
    }
    const sendData = req.body;

    if (!sendData.totalAmount || sendData.sendMoneyFee < 0) {
      console.log(sendData);
      return res.status(400).json({ message: "Invalid input data" });
    }

    // insert
    let result;
    {
      result = await Transaction.insertOne(sendData);
    }
    // check amount by transaction
    let isTransaction;
    let status;
    if (result._id) {
      const transaction = sendData.transaction;
      // update status
      isTransaction = await Transaction.findOne({ transaction });
      status = await Transaction.updateOne(
        { transaction },
        { $set: { status: "sent" } }
      );
      if (!isTransaction) {
        const id = result._id;
        status = await Transaction.updateById(
          { id },
          { $set: { status: "failed" } }
        );
      }
    }

    // Update user account amount
    let updateSender;
    if (isTransaction) {
      updateSender = await Users.updateOne(
        { email },
        { $inc: { amount: -+sendData.finalAmount } }
      );
    }
    // Update receiver's account amount (add)
    let updateReceiver;
    if (isTransaction) {
      updateReceiver = await Users.updateOne(
        { mobileNumber: sendData.receiverMobileNumber },
        { $inc: { amount: +sendData.totalAmount } },
        { upsert: true }
      );
    }

    let adminUpdate;
    // modify admin transaction
    if (isTransaction) {
      const updated = {
        $inc: {
          totalTransactions: 1,
          totalAmountProcessed: sendData.totalAmount,
          totalSendMoneyFees: sendData.sendMoneyFee,
        },
        $set: {
          lastUpdated: new Date(),
        },
      };
      adminUpdate = await AdminTransaction.updateOne({}, updated, {
        upsert: true,
      });
    }
    const data = {
      transaction: isTransaction.transaction,
      status: status.acknowledged > 0 ? "success" : "failed",
      totalAmount: result.totalAmount,
      cost: result.sendMoneyFee,
      timestamp: result.timestamp,
    };

    res.status(200).json({ message: "Send success", data });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// cash-out user to agent
app.post("/cash-out/:email", verifyToken, async (req, res) => {
  try {
    const user = req.user;
    const email = req.params.email;

    if (email !== user.email) {
      return res
        .status(403)
        .json({ message: "Forbidden: Unauthorized access" });
    }

    const cashOutData = req.body;

    // Verify user PIN
    const isUser = await verifyPin(
      cashOutData.pin,
      null,
      cashOutData.mobileNumber
    );
    if (!isUser) {
      return res.status(400).json({ message: "Invalid credential" });
    }

    const { totalAmount, finalAmount, receiverMobileNumber, receiverName } =
      cashOutData;
    if (!totalAmount || !finalAmount) {
      return res.status(400).json({ message: "Invalid transaction data" });
    }

    const adminEarn = +((parseInt(totalAmount) * 0.5) / 100).toFixed(2);
    const agentEarn = +((parseInt(totalAmount) * 1) / 100).toFixed(2);

    // Insert Transaction
    const transaction = await Transaction.create({
      ...cashOutData,
      status: "unsent",
      createdAt: new Date(),
    });

    if (!transaction) {
      return res.status(500).json({ message: "Failed to process transaction" });
    }

    // Update Transaction Status
    let updatedStatus = "failed";
    const isTransaction = await Transaction.findById(transaction._id);

    if (isTransaction) {
      const updateResult = await Transaction.updateOne(
        { transaction: isTransaction.transaction },
        { $set: { status: "sent" } }
      );
      if (updateResult.modifiedCount > 0) {
        updatedStatus = "sent";
      }
    }

    // Update Admin Earnings
    await AdminTransaction.updateOne(
      {},
      {
        $inc: {
          totalTransactions: 1,
          totalAmountProcessed: parseInt(totalAmount),
          totalSendMoneyFees: adminEarn,
        },
        $set: { lastUpdated: new Date() },
      },
      { upsert: true }
    );

    // Update Agent Earnings
    const show = await AgentTransaction.updateOne(
      { agentMobileNumber: receiverMobileNumber },

      {
        $inc: {
          totalTransactions: 1,
          totalAmountProcessed: parseInt(totalAmount),
          totalCommissionEarned: agentEarn,
          totalCashIn: parseInt(totalAmount),
        },
        $set: {
          name: receiverName,
          lastUpdated: new Date(),
        },
      },
      { upsert: true }
    );

    // Update User Balance
    const totalDeduction = parseInt(finalAmount) + adminEarn + agentEarn;
    await Users.updateOne({ email }, { $inc: { amount: -totalDeduction } });

    // Prepare response data
    const data = {
      transactionId: transaction.transaction,
      status: updatedStatus,
      totalAmount: transaction.totalAmount,
      cost: adminEarn + agentEarn,
      timestamp: transaction.createdAt,
    };

    res.status(200).json({ message: "Cash Out Successful", data });
  } catch (error) {
    console.error("Cash Out Error:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
});

// real time notification
// cash in agent to user

io.on("connection", (socket) => {
  console.log("User Connected:", socket.id);

  socket.on("register", (mobileNumber) => {
    userSockets[mobileNumber] = socket.id;
  });
  // Handle user disconnection
  socket.on("disconnect", () => {
    console.log("User Disconnected:", socket.id);
    for (const number in userSockets) {
      if (userSockets[number] === socket.id) {
        delete userSockets[number];
        break;
      }
    }
  });
});

app.post("/cash-in/:email", verifyToken, async (req, res) => {
  try {
    const user = req.user;
    const email = req.params.email;

    if (email !== user.email) {
      return res
        .status(403)
        .json({ message: "Forbidden: Unauthorized access" });
    }

    const {
      pin,
      mobileNumber,
      totalAmount,
      receiverMobileNumber,
      receiverName,
    } = req.body;

    // Verify user PIN
    const isUser = await verifyPin(pin, null, mobileNumber);

    if (!isUser) {
      return res.status(400).json({ message: "Invalid credential" });
    }
    if (!totalAmount) {
      return res.status(400).json({ message: "Invalid transaction data" });
    }

    // Insert Transaction
    const transaction = await Transaction.create({
      ...req.body,
      status: "unsent",
      createdAt: new Date(),
    });

    if (!transaction) {
      return res.status(500).json({ message: "Failed to process transaction" });
    }

    // Update Transaction Status
    let updatedStatus = "failed";
    const isTransaction = await Transaction.findById(transaction._id);

    if (isTransaction) {
      const updateResult = await Transaction.updateOne(
        { _id: isTransaction._id },
        { $set: { status: "sent" } }
      );
      if (updateResult.modifiedCount > 0) {
        updatedStatus = "sent";
      }
    }

    // Update Admin Earnings (No fees, so just tracking total transactions)
    await AdminTransaction.updateOne(
      {},
      {
        $inc: {
          totalTransactions: 1,
          totalAmountProcessed: Number(totalAmount),
        },
        $set: { lastUpdated: new Date() },
      },
      { upsert: true }
    );

    // Update Agent Earnings (No commission, only tracking transactions)
    await AgentTransaction.updateOne(
      { agentMobileNumber: receiverMobileNumber },

      {
        $inc: { totalTransactions: 1, totalAmountProcessed: -totalAmount },
        $set: { lastUpdated: new Date(), name: receiverName },
      },
      { upsert: true }
    );

    // Update User Balance (Adding total amount to user's account)
    await Users.updateOne({ email }, { $inc: { amount: +totalAmount } });
    const notifyUser = await Users.findOne({
      mobileNumber,
    });
    //  real time notification
    if (notifyUser) {
      const userSocketId = userSockets[mobileNumber];
      if (userSocketId) {
        io.to(userSocketId).emit("notification", {
          message: `Cash in success ${totalAmount}৳ .`,
          amount: totalAmount,
          timestamp: new Date(),
        });
      }
    }
    // Prepare response data
    const data = {
      transactionId: transaction._id,
      status: updatedStatus,
      totalAmount: transaction.totalAmount,
      cost: 0, // No fee or cost
      timestamp: transaction.createdAt,
    };

    res.status(200).json({ message: "Cash In Successful", data });
  } catch (error) {
    console.error("Cash In Error:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
});

// agent approve/ remove
app.patch("/agents-approval", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { mobileNumber, approved, name } = req.body;

    // Find the agent by ID
    const agent = await Users.findOne({ mobileNumber });
    if (!agent) {
      return res.status(404).json({ message: "Agent not found" });
    }

    // If the agent is approved
    if (approved) {
      // Update the agent amount
      const update = {
        $set: { approve: true },
      };
      // update
      await Users.updateOne({ mobileNumber }, update);

      // Update Agent Earnings
      await AgentTransaction.updateOne(
        { agentMobileNumber: mobileNumber },

        {
          $inc: {
            totalAmountProcessed: 100000,
          },
          $set: { lastUpdated: new Date(), name: name },
        },
        { upsert: true }
      );

      // Update the admin fund
      await AdminTransaction.updateOne(
        {},
        { $inc: { totalAmountProcessed: 100000 } },
        { upsert: true }
      );

      return res.status(200).json({
        message: "Agent approved and balance updated",
      });
    } else {
      // If not approved,
      await Users.updateOne({ mobileNumber }, { $set: { approve: false } });
      return res.status(200).json({
        message: "Agent request rejected",
      });
    }
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
      error: error.message,
    });
  }
});

// agent transaction
app.get("/agent/transactions/:mobileNumber", verifyToken, async (req, res) => {
  try {
    const mobileNumber = req.params.mobileNumber;

    if (!mobileNumber) {
      res.status(404).json({ message: "Invalid operation" });
      return;
    }
    const isAgent = await Users.findOne({ mobileNumber });
    const role = isAgent.role === "agent";
    if (!role) {
      res.status(403).json({ message: "Forbidden unAuthorized access" });
    }
    const transactions = await AgentTransaction.find({
      agentMobileNumber: mobileNumber,
    });

    res.json({ message: "agent transactions retrieved", transactions });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

//
app.get("/agent/transactions", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const transactions = await AgentTransaction.find({});

    res.json({ message: "agent transactions retrieved", transactions });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});
// get admin
app.get("/agent-approval-status/:email", verifyToken, async (req, res) => {
  try {
    const user = req.user;
    const email = req.params.email;

    if (email !== user.email) {
      return res
        .status(403)
        .json({ message: "Forbidden: Unauthorized access" });
    }

    const result = await Users.findOne({ email });
    const isAgent = result.approve;
    res.status(200).json({ data: isAgent });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.get(
  "/admin/transactions/:email",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const transactions = await AdminTransaction.find({});

      res.json({ message: "Admin transactions retrieved", transactions });
    } catch (error) {
      console.log(error);
      res
        .status(500)
        .json({ message: "Internal server error", error: error.message });
    }
  }
);

app.get("/", (req, res) => {
  res.send("Quick cash server on running.....");
});
server.listen(port, () => {
  console.log(`Quick cash server on running on : ${port}`);
});
