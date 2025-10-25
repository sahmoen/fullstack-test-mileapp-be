import Joi from "joi";

export const taskCreateSchema = Joi.object({
  title: Joi.string().min(1).max(200).required(),
  description: Joi.string().allow("", null),
  status: Joi.string()
    .valid("pending", "in-progress", "done")
    .default("pending"),
  dueDate: Joi.date().optional(),
});

export const taskUpdateSchema = Joi.object({
  title: Joi.string().min(1).max(200).optional(),
  description: Joi.string().allow("", null),
  status: Joi.string().valid("pending", "in-progress", "done").optional(),
  dueDate: Joi.date().optional(),
});
