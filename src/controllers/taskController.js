import { Task } from "../models/Task.js";

export const getTasks = async (req, res) => {
  const {
    page = 1,
    limit = 10,
    sort = "-createdAt",
    status,
    search,
  } = req.query;
  const filter = {};
  if (status) filter.status = status;
  if (search) filter.title = { $regex: search, $options: "i" };

  const total = await Task.countDocuments(filter);
  const tasks = await Task.find(filter)
    .sort(sort)
    .skip((page - 1) * limit)
    .limit(Number(limit));

  res.json({ meta: { total, page, limit }, data: tasks });
};

export const createTask = async (req, res) => {
  const task = await Task.create(req.body);
  res.status(201).json(task);
};

export const updateTask = async (req, res) => {
  const task = await Task.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json(task);
};

export const deleteTask = async (req, res) => {
  await Task.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted successfully" });
};
