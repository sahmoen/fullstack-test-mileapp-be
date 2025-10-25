// src/tests/auth.test.js
import request from "supertest";
import app from "../app.js";
import mongoose from "mongoose";
import { User } from "../models/User.js";

beforeAll(async () => {
  // use test DB - set env MONGO_URI to test db in CI or local before running
  await mongoose.connect(process.env.MONGO_URI);
  await User.deleteMany({});
});

afterAll(async () => {
  await User.deleteMany({});
  await mongoose.disconnect();
});

describe("Auth endpoints", () => {
  it("should register a new user", async () => {
    const res = await request(app).post("/login/register").send({
      username: "testuser",
      email: "test@example.com",
      password: "123456",
    });
    expect(res.statusCode).toBe(201);
    expect(res.body).toHaveProperty("accessToken");
  });

  it("should login with email", async () => {
    const res = await request(app).post("/login/login").send({
      identifier: "test@example.com",
      password: "123456",
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty("accessToken");
  });
});
