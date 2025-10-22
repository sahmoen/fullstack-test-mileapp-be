import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { User } from "../models/User.js";

/**
 * POST /register
 * - Jika belum ada admin, siapa pun bisa register pertama kali
 * - Jika sudah ada admin, hanya admin (dengan token) yang boleh membuat user baru
 */
export const register = async (req, res) => {
  try {
    const { username, password, role = "user" } = req.body;

    // Cek apakah sudah ada admin di sistem
    const adminExists = await User.findOne({ role: "admin" });

    // Kalau admin sudah ada, pastikan yang register ini admin juga
    if (adminExists) {
      const authHeader = req.headers.authorization;
      if (!authHeader)
        return res
          .status(403)
          .json({ message: "Only admin can create new users" });

      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const currentUser = await User.findById(decoded.id);

      if (!currentUser || currentUser.role !== "admin") {
        return res
          .status(403)
          .json({ message: "You are not authorized to create users" });
      }
    }

    // Cegah duplikasi username
    const existing = await User.findOne({ username });
    if (existing)
      return res.status(400).json({ message: "Username already exists" });

    // Buat user baru
    const user = await User.create({ username, password, role });

    res.status(201).json({
      message: "User registered successfully",
      user: { id: user._id, username: user.username, role: user.role },
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

/**
 * POST /login
 */
export const login = async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({
    token,
    user: { username: user.username, role: user.role },
  });
};
