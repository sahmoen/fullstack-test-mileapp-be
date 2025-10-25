// src/controllers/authController.js
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { User } from "../models/User.js";
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from "../validation/authValidation.js";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../utils/generateToken.js";
import { sendEmail } from "../utils/sendEmail.js";

/**
 * Helper responses
 */
const sendSuccess = (res, statusCode, payload) =>
  res.status(statusCode).json({ status: "success", statusCode, ...payload });
const sendError = (res, statusCode, message) =>
  res.status(statusCode).json({ status: "error", statusCode, message });

/**
 * POST /login/register
 */
export const register = async (req, res, next) => {
  try {
    const { error } = registerSchema.validate(req.body);
    if (error) return sendError(res, 400, error.details[0].message);

    const { username, email, password, role = "user" } = req.body;

    // check duplicate username/email
    const existing = await User.findOne({
      $or: [{ username }, { email }],
    });
    if (existing)
      return sendError(res, 400, "Username or email already exists");

    // only allow creating admin if requester is admin (and an admin already exists)
    const adminExists = await User.findOne({ role: "admin" });
    if (role === "admin" && adminExists) {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token)
        return sendError(res, 403, "Only admin can create another admin");
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const requester = await User.findById(decoded.id);
        if (!requester || requester.role !== "admin")
          return sendError(res, 403, "Unauthorized to create admin");
      } catch (err) {
        return sendError(res, 403, "Invalid token");
      }
    }

    const user = await User.create({ username, email, password, role });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return sendSuccess(res, 201, {
      message: "Registration successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
      accessToken,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /login/login
 * body: { identifier, password }  (identifier = username or email)
 */
export const login = async (req, res, next) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) return sendError(res, 400, error.details[0].message);

    const { identifier, password } = req.body;
    const user = await User.findOne({
      $or: [{ username: identifier }, { email: identifier }],
    });
    if (!user) return sendError(res, 401, "Invalid credentials");

    const valid = await user.matchPassword(password);
    if (!valid) return sendError(res, 401, "Invalid credentials");

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return sendSuccess(res, 200, {
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
      accessToken,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /login/refresh
 * reads refreshToken from cookie and returns new access token
 */
export const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return sendError(res, 401, "No refresh token provided");

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      return sendError(res, 401, "Invalid or expired refresh token");
    }

    const user = await User.findById(decoded.id);
    if (!user) return sendError(res, 401, "User not found");

    const accessToken = generateAccessToken(user);
    return sendSuccess(res, 200, { accessToken });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /login/logout
 */
export const logout = async (req, res, next) => {
  try {
    res.clearCookie("refreshToken", {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
    });
    return sendSuccess(res, 200, { message: "Logged out successfully" });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /login/forgot-password
 * NOTE: per request, this endpoint DOES NOT accept email in body.
 * It requires the user to be authenticated (req.user) and will send
 * the reset link/token to the email associated with the logged-in account.
 */
export const forgotPassword = async (req, res, next) => {
  try {
    // ensure user is authenticated (protect middleware must be used on this route)
    const user = req.user;
    if (!user)
      return sendError(
        res,
        401,
        "You must be logged in to request password reset"
      );

    // generate token & store hash
    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // expire in 10 minutes
    user.resetPasswordToken = resetHash;
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const resetLink = `${req.protocol}://${req.get(
      "host"
    )}/login/reset-password/${resetToken}`;

    const message = `You requested a password reset.\n\nUse the token below (valid for 10 minutes) or click the link:\n\nToken: ${resetToken}\n\nLink: ${resetLink}\n\nIf you did not request this, ignore this message.`;

    // send email to user's registered email
    await sendEmail(user.email, "Password Reset Request", message);

    return sendSuccess(res, 200, {
      message: "Password reset token sent to your email (valid 10 minutes)",
    });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /login/reset-password
 * body: { token, password }
 */
export const resetPassword = async (req, res, next) => {
  try {
    const { error } = resetPasswordSchema.validate(req.body);
    if (error) return sendError(res, 400, error.details[0].message);

    const { token, password } = req.body;
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!user) return sendError(res, 400, "Invalid or expired token");

    user.password = password; // pre-save hook in model will hash
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return sendSuccess(res, 200, { message: "Password reset successful" });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /login/me
 */
export const getProfile = async (req, res, next) => {
  try {
    const user = req.user;
    if (!user) return sendError(res, 401, "Unauthorized");
    return sendSuccess(res, 200, { user });
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /login/me
 * body: { email?, username?, password? }
 */
export const updateProfile = async (req, res, next) => {
  try {
    const { email, username, password } = req.body;
    const user = await User.findById(req.user._id);
    if (!user) return sendError(res, 404, "User not found");

    if (email) {
      const ex = await User.findOne({ email });
      if (ex && String(ex._id) !== String(user._id))
        return sendError(res, 400, "Email already in use");
      user.email = email;
    }
    if (username) {
      const ex2 = await User.findOne({ username });
      if (ex2 && String(ex2._id) !== String(user._id))
        return sendError(res, 400, "Username already in use");
      user.username = username;
    }
    if (password) user.password = password;

    await user.save();

    return sendSuccess(res, 200, {
      message: "Profile updated",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    next(err);
  }
};
