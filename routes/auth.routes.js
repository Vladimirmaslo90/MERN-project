const { Router } = require("express");
const User = require("../models/User");
const bycript = require("bcryptjs");
const { check, validationResult } = require("express-validator");
const router = Router();

//api/auth/register
router.post(
  "/register",
  [
    check("email", "Incorrect email").isEmail(),
    check("passowrd", "Please input valid password. Min 6 chars").isLength({
      min: 6
    })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Incorrect data during registration"
        });
      }

      const { email, password } = req.body;

      const candidate = await User.findOne({
        email
      });
      if (candidate) {
        res
          .status(400)
          .json({ message: "This email address is already exists" });
      }

      const hashedPassword = await bycript.hash(password, 12);
      const user = new User({ email, password: hashedPassword });
      await user.save();

      res.status(200).json({ message: "User has been created" });
    } catch (e) {
      res.status(500).json({
        message: "Someting went wrong. Please try again"
      });
    }
  }
);

//api/auth/login
router.post(
  "/login",
  [
    check("email", "Please enter valid email")
      .normalizeEmail()
      .isEmail(),
    check("password", "please enter valid password").exists()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: "Incorrect data during login"
        });
      }
    } catch (e) {
      res.status(500).json({
        message: "Someting went wrong. Please try again"
      });
    }
  }
);

module.exports = router;
