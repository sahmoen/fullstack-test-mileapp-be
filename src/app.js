import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import { connectDB } from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import taskRoutes from "./routes/taskRoutes.js";

dotenv.config();
connectDB();

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

app.use("/login", authRoutes);
app.use("/tasks", taskRoutes);

export default app;
