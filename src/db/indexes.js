import mongoose from "mongoose";
import { connectDB } from "../config/db.js";
import { Task } from "../models/Task.js";
import { User } from "../models/User.js";

await connectDB();

await Task.collection.createIndex({
  title: "text",
  description: "text",
  status: 1,
  createdAt: -1,
});
await User.collection.createIndex({ username: 1 }, { unique: true });
await User.collection.createIndex({ email: 1 }, { unique: true });

console.log("Indexes created");
process.exit(0);
