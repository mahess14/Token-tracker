import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { User, Sale, Purchase, PRODUCTS } from "./models.js";

dotenv.config();

const app = express();

/* =========================
   MIDDLEWARE
========================= */

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

/* =========================
   ENVIRONMENT VARIABLES
========================= */

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5000;

if (!MONGO_URI) {
  console.error("❌ MONGO_URI is missing");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET is missing");
  process.exit(1);
}

/* =========================
   HELPER
========================= */

const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    db:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
  });
});

/* =========================
   AUTH HELPERS
========================= */

const makeToken = (user) =>
  jwt.sign(
    {
      id: user._id.toString(),
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );

const publicUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
});

/* =========================
   REGISTER
========================= */

app.post(
  "/api/auth/register",
  wrap(async (req, res) => {
    const { name, email, password } = req.body;

    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({
        error: "Name, email and password are required",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters",
      });
    }

    const cleanEmail = email.toLowerCase().trim();

    const exists = await User.findOne({
      email: cleanEmail,
    });

    if (exists) {
      return res.status(400).json({
        error: "An account with this email already exists",
      });
    }

    const user = await User.create({
      name: name.trim(),
      email: cleanEmail,
      passwordHash: await bcrypt.hash(password, 10),
    });

    res.status(201).json({
      token: makeToken(user),
      user: publicUser(user),
    });
  })
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/auth/login",
  wrap(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const cleanEmail = email.toLowerCase().trim();

    const user = await User.findOne({
      email: cleanEmail,
    });

    if (
      !user ||
      !(await bcrypt.compare(password, user.passwordHash))
    ) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    res.json({
      token: makeToken(user),
      user: publicUser(user),
    });
  })
);

/* =========================
   AUTH MIDDLEWARE
========================= */

const auth = wrap(async (req, res, next) => {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: "Please log in",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: "Please log in",
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Session expired, please log in again",
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/auth/me", auth, (req, res) => {
  res.json({
    user: publicUser(req.user),
  });
});

/* =========================
   STOCK CALCULATION
========================= */

async function stockByProduct(userId) {
  const match = {
    $match: {
      user: new mongoose.Types.ObjectId(userId),
    },
  };

  const [bought, sold] = await Promise.all([
    Purchase.aggregate([
      match,
      {
        $group: {
          _id: "$product",
          qty: {
            $sum: "$quantity",
          },
          cost: {
            $sum: "$amount",
          },
        },
      },
    ]),

    Sale.aggregate([
      match,
      {
        $group: {
          _id: "$product",
          qty: {
            $sum: "$quantity",
          },
          revenue: {
            $sum: "$amount",
          },
        },
      },
    ]),
  ]);

  return PRODUCTS.map((product) => {
    const boughtProduct =
      bought.find((item) => item._id === product) || {
        qty: 0,
        cost: 0,
      };

    const soldProduct =
      sold.find((item) => item._id === product) || {
        qty: 0,
        revenue: 0,
      };

    return {
      product,

      boughtQty: boughtProduct.qty,

      soldQty: soldProduct.qty,

      inStock:
        boughtProduct.qty - soldProduct.qty,

      stockCost: boughtProduct.cost,

      sales: soldProduct.revenue,
    };
  });
}

/* =========================
   VALIDATE PURCHASE / SALE
========================= */

function readEntry(body, priceField) {
  const quantity = Number(body.quantity);
  const price = Number(body[priceField]);

  if (!body.date) {
    return {
      error: "Date is required",
    };
  }

  if (!Number.isInteger(quantity) || quantity < 1) {
    return {
      error: "Quantity must be at least 1",
    };
  }

  if (!PRODUCTS.includes(body.product)) {
    return {
      error: "Select a valid token / product",
    };
  }

  if (
    body[priceField] === "" ||
    body[priceField] == null ||
    !Number.isFinite(price) ||
    price < 0
  ) {
    return {
      error: "Enter a valid price",
    };
  }

  return {
    quantity,
    price,
    amount: quantity * price,
  };
}

/* =========================
   SALES
========================= */

app.get(
  "/api/sales",
  auth,
  wrap(async (req, res) => {
    const sales = await Sale.find({
      user: req.user._id,
    }).sort({
      date: -1,
      createdAt: -1,
    });

    res.json(sales);
  })
);

app.post(
  "/api/sales",
  auth,
  wrap(async (req, res) => {
    const entry = readEntry(
      req.body,
      "sellingPrice"
    );

    if (entry.error) {
      return res.status(400).json({
        error: entry.error,
      });
    }

    const stockList = await stockByProduct(
      req.user._id
    );

    const stock = stockList.find(
      (item) => item.product === req.body.product
    );

    if (!stock) {
      return res.status(400).json({
        error: "Product not found",
      });
    }

    if (entry.quantity > stock.inStock) {
      return res.status(400).json({
        error: `Only ${stock.inStock} × ${req.body.product} in stock`,
      });
    }

    const sale = await Sale.create({
      user: req.user._id,
      date: req.body.date,
      quantity: entry.quantity,
      product: req.body.product,
      sellingPrice: entry.price,
      customerName:
        req.body.customerName || "",
      amount: entry.amount,
    });

    res.status(201).json(sale);
  })
);

/* =========================
   DELETE SALE
========================= */

app.delete(
  "/api/sales/:id",
  auth,
  wrap(async (req, res) => {
    await Sale.deleteOne({
      _id: req.params.id,
      user: req.user._id,
    });

    res.json({
      ok: true,
    });
  })
);

/* =========================
   PURCHASES
========================= */

app.get(
  "/api/purchases",
  auth,
  wrap(async (req, res) => {
    const purchases = await Purchase.find({
      user: req.user._id,
    }).sort({
      date: -1,
      createdAt: -1,
    });

    res.json(purchases);
  })
);

/* =========================
   ADD PURCHASE
========================= */

app.post(
  "/api/purchases",
  auth,
  wrap(async (req, res) => {
    const entry = readEntry(
      req.body,
      "costPrice"
    );

    if (entry.error) {
      return res.status(400).json({
        error: entry.error,
      });
    }

    const purchase = await Purchase.create({
      user: req.user._id,
      date: req.body.date,
      quantity: entry.quantity,
      product: req.body.product,
      costPrice: entry.price,
      supplierName:
        req.body.supplierName || "",
      amount: entry.amount,
    });

    res.status(201).json(purchase);
  })
);

/* =========================
   DELETE PURCHASE
========================= */

app.delete(
  "/api/purchases/:id",
  auth,
  wrap(async (req, res) => {
    const purchase = await Purchase.findOne({
      _id: req.params.id,
      user: req.user._id,
    });

    if (!purchase) {
      return res.json({
        ok: true,
      });
    }

    const stockList = await stockByProduct(
      req.user._id
    );

    const stock = stockList.find(
      (item) => item.product === purchase.product
    );

    if (
      stock &&
      stock.inStock - purchase.quantity < 0
    ) {
      return res.status(400).json({
        error:
          "Can't delete: some of these tokens are already sold",
      });
    }

    await purchase.deleteOne();

    res.json({
      ok: true,
    });
  })
);

/* =========================
   SUMMARY / DASHBOARD
========================= */

app.get(
  "/api/summary",
  auth,
  wrap(async (req, res) => {
    const products = await stockByProduct(
      req.user._id
    );

    const sum = (key) =>
      products.reduce(
        (total, product) =>
          total + Number(product[key] || 0),
        0
      );

    const totalSales = sum("sales");
    const stockCost = sum("stockCost");

    res.json({
      totalSales,

      soldQty: sum("soldQty"),

      stockCost,

      boughtQty: sum("boughtQty"),

      profit: totalSales - stockCost,

      tokensInStock: sum("inStock"),

      products,
    });
  })
);

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", (_req, res) => {
  res.json(PRODUCTS);
});

/* =========================
   404 API
========================= */

app.use("/api", (_req, res) => {
  res.status(404).json({
    error: "API route not found",
  });
});

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, _req, res, _next) => {
    console.error("❌ Server error:", err);

    res.status(500).json({
      error:
        err.message || "Server error",
    });
  }
);

/* =========================
   MONGODB + SERVER
========================= */

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected");

    app.listen(PORT, () => {
      console.log(
        `🚀 API running on port ${PORT}`
      );
    });
  })
  .catch((err) => {
    console.error(
      "❌ MongoDB connection error:",
      err.message
    );

    process.exit(1);
  });