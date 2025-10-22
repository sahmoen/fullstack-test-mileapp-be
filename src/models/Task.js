import mongoose from "mongoose";

const taskSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: String,
    status: {
      type: String,
      enum: ["pending", "in-progress", "done"],
      default: "pending",
    },
    dueDate: Date,
  },
  { timestamps: true }
);

export const Task = mongoose.model("Task", taskSchema);
