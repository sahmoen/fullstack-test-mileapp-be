import mongoose from "mongoose";
import { Task } from "../models/Task.js";
import {
  taskCreateSchema,
  taskUpdateSchema,
} from "../validation/taskValidation.js";

const sendSuccess = (res, statusCode, payload) =>
  res.status(statusCode).json({ status: "success", statusCode, ...payload });
const sendError = (res, statusCode, message) =>
  res.status(statusCode).json({ status: "error", statusCode, message });

// =================== GET TASKS ===================
export const getTasks = async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 10,
      sort = "-createdAt",
      status,
      search,
    } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const total = await Task.countDocuments(filter);
    const pageInt = parseInt(page);
    const limitInt = parseInt(limit);

    const tasks = await Task.find(filter)
      .sort(sort)
      .skip((pageInt - 1) * limitInt)
      .limit(limitInt);

    const meta = {
      total,
      page: pageInt,
      limit: limitInt,
      pages: Math.ceil(total / limitInt),
    };

    return sendSuccess(res, 200, { meta, data: tasks });
  } catch (err) {
    next(err);
  }
};

// =================== CREATE TASK ===================
// export const createTask = async (req, res, next) => {
//   try {
//     const { error } = taskCreateSchema.validate(req.body);
//     if (error) return sendError(res, 400, error.details[0].message);

//     const task = await Task.create(req.body);
//     return sendSuccess(res, 201, { data: task });
//   } catch (err) {
//     next(err);
//   }
// };
export const createTask = async (req, res) => {
  try {
    const { error } = taskSchema.validate(req.body);
    if (error) return sendError(res, 400, error.details[0].message);

    const newTask = await Task.create({
      ...req.body,
      user: req.user.id,
    });

    res.status(201).json(newTask);
  } catch (err) {
    console.error(err);
    sendError(res, 500, "Failed to create task");
  }
};

// =================== UPDATE TASK ===================
export const updateTask = async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id))
      return sendError(res, 400, "Invalid task id");

    const { error } = taskUpdateSchema.validate(req.body);
    if (error) return sendError(res, 400, error.details[0].message);

    const task = await Task.findByIdAndUpdate(id, req.body, { new: true });
    if (!task) return sendError(res, 404, "Task not found");

    return sendSuccess(res, 200, { data: task });
  } catch (err) {
    next(err);
  }
};

// =================== DELETE TASK ===================
export const deleteTask = async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id))
      return sendError(res, 400, "Invalid task id");

    const task = await Task.findByIdAndDelete(id);
    if (!task) return sendError(res, 404, "Task not found");

    return sendSuccess(res, 200, { message: "Task deleted successfully" });
  } catch (err) {
    next(err);
  }
};
