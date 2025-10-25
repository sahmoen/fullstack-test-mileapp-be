import express from "express";
import { protect } from "../middleware/authMiddleware.js";
import {
  register,
  login,
  refreshToken,
  forgotPassword,
  resetPassword,
  verifyResetToken,
  getProfile,
  updateProfile,
  logout,
} from "../controllers/authController.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/refresh", refreshToken);
router.post("/logout", protect, logout);
router.get("/me", protect, getProfile);
router.patch("/me", protect, updateProfile);

// Password reset routes
router.post("/forgot-password", forgotPassword);
router.get("/verify-reset-token/:token", verifyResetToken);
router.post("/reset-password", resetPassword);

export default router;
