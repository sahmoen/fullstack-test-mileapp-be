import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import helmet from "helmet";
import xss from "xss";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import { connectDB } from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import taskRoutes from "./routes/taskRoutes.js";
import { errorHandler } from "./middleware/errorMiddleware.js";

dotenv.config();
connectDB();

const app = express();

// Security middlewares
app.use(helmet());
app.use(cors());
app.use(cookieParser());
app.use(morgan("dev"));
app.use(express.json());

// Sanitizer untuk XSS & NoSQL Injection
const sanitizeObject = (obj) => {
  if (!obj || typeof obj !== "object") return obj;
  for (const key of Object.keys(obj)) {
    const val = obj[key];

    // hapus key berbahaya ($, .)
    if (key.includes("$") || key.includes(".")) {
      delete obj[key];
      continue;
    }

    if (typeof val === "string") {
      obj[key] = xss(val);
    } else if (typeof val === "object") {
      sanitizeObject(val);
    }
  }
};

// Terapkan sanitizer manual untuk semua request
app.use((req, res, next) => {
  try {
    if (req.body) sanitizeObject(req.body);
    if (req.query && typeof req.query === "object") sanitizeObject(req.query);
    if (req.params) sanitizeObject(req.params);
  } catch (err) {
    console.error("Sanitizer error:", err);
  }
  next();
});

// Rate limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: "Too many requests. Please try again later." },
});
app.use("/login", authLimiter);

// Routes
app.use("/login", authRoutes);
app.use("/tasks", taskRoutes);

// Error handler
app.use(errorHandler);

export default app;
