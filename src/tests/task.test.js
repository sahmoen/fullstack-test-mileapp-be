import request from "supertest";
import app from "../app.js";
import mongoose from "mongoose";
import { Task } from "../models/Task.js";
import { User } from "../models/User.js";

let token;

beforeAll(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  await Task.deleteMany({});
  await User.deleteMany({});
  const userRes = await request(app)
    .post("/login/register")
    .send({ username: "tuser", email: "t@t.com", password: "123456" });
  token = userRes.body.accessToken;
});

afterAll(async () => {
  await Task.deleteMany({});
  await User.deleteMany({});
  await mongoose.disconnect();
});

describe("Tasks", () => {
  it("create, get, update, delete", async () => {
    const createRes = await request(app)
      .post("/tasks")
      .set("Authorization", `Bearer ${token}`)
      .send({ title: "task 1", description: "desc" });
    expect(createRes.statusCode).toBe(201);
    const id = createRes.body.data._id;

    const getRes = await request(app)
      .get("/tasks")
      .set("Authorization", `Bearer ${token}`);
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.meta).toHaveProperty("total");

    const updateRes = await request(app)
      .put(`/tasks/${id}`)
      .set("Authorization", `Bearer ${token}`)
      .send({ status: "done" });
    expect(updateRes.statusCode).toBe(200);
    expect(updateRes.body.data.status).toBe("done");

    const delRes = await request(app)
      .delete(`/tasks/${id}`)
      .set("Authorization", `Bearer ${token}`);
    expect(delRes.statusCode).toBe(200);
  });
});
