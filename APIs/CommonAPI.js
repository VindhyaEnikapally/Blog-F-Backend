import exp from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { authenticate } from "../services/authService.js";
import { UserTypeModel } from "../models/UserModel.js";
import { verifyToken } from "../middlewares/verifyToken.js";

export const commonRouter = exp.Router();

commonRouter.post("/register", async (req, res) => {
  try {
    console.log("BODY:", req.body);

    const userObj = {
  firstName: req.body.firstName,
  lastName: req.body.lastName,
  email: req.body.email,
  password: req.body.password,
  role: req.body.role,
  profileImageUrl: req.body.profileImageUrl,
};

    const newUser = new UserTypeModel(userObj);

    await newUser.validate();

    newUser.password = await bcrypt.hash(newUser.password, 10);

    const savedUser = await newUser.save();

    return res.status(201).json({
      message: "User registered",
      payload: savedUser,
    });

  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Register failed",
      error: err.message,
    });
  }
});

// =======================
// 🔐 LOGIN
// =======================
commonRouter.post("/login", async (req, res) => {
  try {
    const userCred = req.body;

    const { token, user } = await authenticate(userCred);

    // IMPORTANT: cookie settings (DEV + PROD safe)
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,     // change to true in production (Render HTTPS)
      sameSite: "none",   // use "none" in production if frontend is separate domain
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    return res.status(200).json({
      message: "login success",
      payload: user,
    });

  } catch (err) {
    return res.status(err.status || 401).json({
      message: "login failed",
      error: err.message,
    });
  }
});


// =======================
// 🚪 LOGOUT
// =======================
commonRouter.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });

  return res.status(200).json({
    message: "Logged out successfully",
  });
});


// =======================
// 🔑 CHANGE PASSWORD
// =======================
commonRouter.put("/change-password", async (req, res) => {
  try {
    const { email, currentPassword, newPassword } = req.body;

    if (currentPassword === newPassword) {
      return res.status(400).json({
        message: "New password must be different",
      });
    }

    const user = await UserTypeModel.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "Account not found",
      });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Current password incorrect",
      });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.status(200).json({
      message: "Password changed successfully",
    });

  } catch (err) {
    return res.status(500).json({
      message: err.message,
    });
  }
});


// =======================
// 🔍 CHECK AUTH
// =======================
commonRouter.get(
  "/check-auth",
  verifyToken("USER", "AUTHOR", "ADMIN"),
  (req, res) => {
    return res.status(200).json({
      message: "authenticated",
      payload: req.user,
    });
  }
);