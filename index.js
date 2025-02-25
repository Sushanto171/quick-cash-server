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
    origin: ["http://localhost:5173", "https://quick-cash-1.netlify.app"],
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
    amount: { type: Number, default: 0 },
    status: { type: Boolean, default: false },
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
    required: true,
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

// auth related apis
app.post("/log-in", async (req, res) => {
  try {
    const { mobileNumber, email, pin } = req.body;
    // Check if any field is missing
    if (!pin) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // compare pin
    const user = await verifyPin(pin, email, mobileNumber);
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

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

    // bonus 40tk
    let bonus;
    if (result?._id && result?.role === "user") {
      const email = result.email;
      bonus = await Users.updateOne({ email }, { $set: { amount: 40 } });
    }
    const userData = {
      name: user.name,
      role: user.role,
      email: user.email,
      mobileNumber: user.mobileNumber,
      amount: bonus ? 40 : result.amount,
    };
    // token
    const token = tokenGenerate(result);
    res.status(201).json({
      message: "User registered successfully",
      token,
      data: userData,
      bonus,
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
    console.log("RegisterErr", error);
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

// send many apis
app.post("/send-many/:email", verifyToken, async (req, res) => {
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

// cash-out
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

    const { totalAmount, finalAmount, receiverMobileNumber } = cashOutData;
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
    await AgentTransaction.updateOne(
      { agentMobileNumber: receiverMobileNumber },
      {
        $inc: {
          totalTransactions: 1,
          totalAmountProcessed: parseInt(totalAmount),
          totalCommissionEarned: agentEarn,
          totalCashIn: parseInt(totalAmount),
        },
        $set: { lastUpdated: new Date() },
      },
      { upsert: true }
    );

    // Update User Balance
    const totalDeduction = parseInt(finalAmount) + adminEarn + agentEarn;
    await Users.updateOne({ email }, { $inc: { amount: -totalDeduction } });

    // Prepare response data
    const data = {
      transactionId: transaction._id,
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

// cash in
app.post("/cash-in", verifyToken, async (req, res) => {
  try {
    const { email, amount, transactionId } = req.body;

    // Validate input
    if (!email || !amount || amount < 50) {
      return res
        .status(400)
        .json({ message: "Invalid amount. Minimum 50 BDT required!" });
    }

    // Check if user exists
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    // Insert cash-in transaction
    const transaction = {
      email,
      transactionId,
      type: "cashin",
      amount: Number(amount),
      timestamp: new Date().toISOString(),
      status: "success",
    };
    await transactionsCollection.insertOne(transaction);

    // Update user's balance
    const newBalance = user.balance + Number(amount);
    await usersCollection.updateOne(
      { email },
      { $set: { balance: newBalance } }
    );

    // Response
    res.status(200).json({
      message: "Cash In Successful!",
      transactionId,
      newBalance,
    });
  } catch (error) {
    console.error("Cash In Error:", error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
});

// recent transaction

app.get("/", (req, res) => {
  res.send("Quick cash server on running.....");
});
app.listen(port, () => {
  console.log(`Quick cash server on running on : ${port}`);
});
