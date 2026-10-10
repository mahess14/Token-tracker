
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User, Sale, Purchase, PRODUCTS } from "./models.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
  console.error("Missing MONGO_URI or JWT_SECRET environment variable.");
  process.exit(1);
}

app.use(cors({
  origin: process.env.FRONTEND_URL || true
}));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const publicUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email
});

const makeToken = (user) =>
  jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

// Health check
app.get("/", (_req, res) => {
  res.json({ ok: true, message: "Token Tracker API is running" });
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    db: mongoose.connection.readyState === 1
      ? "connected"
      : "disconnected"
  });
});

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({ error: "Please log in" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired login session"
    });
  }
};

// Register
app.post("/api/auth/register", wrap(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name?.trim() || !email?.trim() || !password) {
    return res.status(400).json({
      error: "Name, email and password are required"
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "Password must contain at least 6 characters"
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const existing = await User.findOne({ email: normalizedEmail });

  if (existing) {
    return res.status(409).json({
      error: "Email already registered"
    });
  }

  const user = await User.create({
    name: name.trim(),
    email: normalizedEmail,
    passwordHash: await bcrypt.hash(password, 10)
  });

  res.status(201).json({
    token: makeToken(user),
    user: publicUser(user)
  });
}));

// Login
app.post("/api/auth/login", wrap(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required"
    });
  }

  const user = await User.findOne({
    email: email.trim().toLowerCase()
  });

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({
      error: "Invalid email or password"
    });
  }

  res.json({
    token: makeToken(user),
    user: publicUser(user)
  });
}));

// Current user
app.get("/api/auth/me", auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Products
app.get("/api/products", (_req, res) => {
  res.json(PRODUCTS);
});

// Stock calculations
async function stockByProduct(userId) {
  const userObjectId = new mongoose.Types.ObjectId(userId);

  const [purchases, sales] = await Promise.all([
    Purchase.aggregate([
      { $match: { user: userObjectId } },
      {
        $group: {
          _id: "$product",
          qty: { $sum: "$quantity" },
          cost: { $sum: "$amount" }
        }
      }
    ]),
    Sale.aggregate([
      { $match: { user: userObjectId } },
      {
        $group: {
          _id: "$product",
          qty: { $sum: "$quantity" },
          revenue: { $sum: "$amount" }
        }
      }
    ])
  ]);

  return PRODUCTS.map((product) => {
    const purchase = purchases.find(p => p._id === product);
    const sale = sales.find(s => s._id === product);

    const boughtQty = purchase?.qty || 0;
    const soldQty = sale?.qty || 0;

    return {
      product,
      boughtQty,
      soldQty,
      inStock: boughtQty - soldQty,
      stockCost: purchase?.cost || 0,
      sales: sale?.revenue || 0
    };
  });
}

function validateEntry(body, priceField) {
  const quantity = Number(body.quantity);
  const price = Number(body[priceField]);

  if (!body.date) return { error: "Date is required" };

  if (!Number.isInteger(quantity) || quantity < 1) {
    return { error: "Quantity must be at least 1" };
  }

  if (!PRODUCTS.includes(body.product)) {
    return { error: "Select a valid product" };
  }

  if (
    body[priceField] === "" ||
    body[priceField] == null ||
    !Number.isFinite(price) ||
    price < 0
  ) {
    return { error: "Enter a valid price" };
  }

  return {
    quantity,
    price,
    amount: quantity * price
  };
}

// Get sales
app.get("/api/sales", auth, wrap(async (req, res) => {
  const sales = await Sale.find({ user: req.user._id })
    .sort({ date: -1, createdAt: -1 });

  res.json(sales);
}));

// Add sale
app.post("/api/sales", auth, wrap(async (req, res) => {
  const entry = validateEntry(req.body, "sellingPrice");

  if (entry.error) {
    return res.status(400).json({ error: entry.error });
  }

  const stock = (await stockByProduct(req.user._id))
    .find(item => item.product === req.body.product);

  if (!stock || entry.quantity > stock.inStock) {
    return res.status(400).json({
      error: `Only ${stock?.inStock || 0} units in stock`
    });
  }

  const sale = await Sale.create({
    user: req.user._id,
    date: req.body.date,
    product: req.body.product,
    quantity: entry.quantity,
    sellingPrice: entry.price,
    customerName: req.body.customerName || "",
    amount: entry.amount
  });

  res.status(201).json(sale);
}));

// Delete sale
app.delete("/api/sales/:id", auth, wrap(async (req, res) => {
  const result = await Sale.deleteOne({
    _id: req.params.id,
    user: req.user._id
  });

  if (!result.deletedCount) {
    return res.status(404).json({ error: "Sale not found" });
  }

  res.json({ ok: true });
}));

// Get purchases
app.get("/api/purchases", auth, wrap(async (req, res) => {
  const purchases = await Purchase.find({ user: req.user._id })
    .sort({ date: -1, createdAt: -1 });

  res.json(purchases);
}));

// Add purchase
app.post("/api/purchases", auth, wrap(async (req, res) => {
  const entry = validateEntry(req.body, "costPrice");

  if (entry.error) {
    return res.status(400).json({ error: entry.error });
  }

  const purchase = await Purchase.create({
    user: req.user._id,
    date: req.body.date,
    product: req.body.product,
    quantity: entry.quantity,
    costPrice: entry.price,
    supplierName: req.body.supplierName || "",
    amount: entry.amount
  });

  res.status(201).json(purchase);
}));

// Delete purchase
app.delete("/api/purchases/:id", auth, wrap(async (req, res) => {
  const purchase = await Purchase.findOne({
    _id: req.params.id,
    user: req.user._id
  });

  if (!purchase) {
    return res.status(404).json({ error: "Purchase not found" });
  }

  const stock = (await stockByProduct(req.user._id))
    .find(item => item.product === purchase.product);

  if (stock && stock.inStock - purchase.quantity < 0) {
    return res.status(400).json({
      error: "Cannot delete: some purchased tokens have already been sold"
    });
  }

  await purchase.deleteOne();
  res.json({ ok: true });
}));

// Dashboard summary
app.get("/api/summary", auth, wrap(async (req, res) => {
  const products = await stockByProduct(req.user._id);
  const sum = (key) =>
    products.reduce((total, item) => total + item[key], 0);

  const totalSales = sum("sales");
  const stockCost = sum("stockCost");

  res.json({
    totalSales,
    soldQty: sum("soldQty"),
    stockCost,
    boughtQty: sum("boughtQty"),
    profit: totalSales - stockCost,
    tokensInStock: sum("inStock"),
    products
  });
}));

// Unknown routes
app.use((req, res) => {
  res.status(404).json({
    error: "API route not found",
    method: req.method,
    path: req.originalUrl
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("API error:", err);

  if (res.headersSent) return next(err);

  res.status(500).json({
    error: "Internal server error"
  });
});

// Start after MongoDB connects
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Token Tracker API running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  });
