const express = require("express");
const model = require("../model/model");
const bcrypt = require("bcrypt");
const  authenticate = require("../GenToken");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const router = express.Router();
const shortid = require("shortid");





// const jwt = require("jsonwebtoken");

// Replace 'YOUR_SECRET_KEY' with your actual secret key


const generateToken = (id) => jwt.sign(
    { id },
    process.env.SECRET_KEY,
    { expiresIn: "20d" }
);








router.get("/users", async (req, res) => {
  const user = await model.find();
  if (!user) {
    return res.status(404).json({ message: "not found" });
  }
  res.status(200).json(user);
});

router.post("/signup", async (req, res) => {
  const { Name, Email, Password } = req.body;
  const user = await model.findOne({ Email });
  if (!user) {
    const hashedPassword = await bcrypt.hash(Password, 10);

    const newUser = new model({ Name, Email, Password: hashedPassword });

    await newUser.save();

    return res.status(201).json({ message: "user Created" });
  }
  res.status(404).json({ message: "user Already exist" });
});


router.post("/login", async (req, res) => {
  const { Email, Password } = req.body;

  try {
    const user = await model.findOne({ Email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const passwordValidate = await bcrypt.compare(Password, user.Password);

    if (!passwordValidate) {
      return res.status(401).json({ message: "Incorrect email or password" });
    }

    const token = generateToken(user._id);
    res.json({ user, token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "An error occurred during login" });
  }
});

router.post("/resetpassword", async (req, res) => {
  const { Email } = req.body;
  const user = await model.findOne({ Email });
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const resetToken = jwt.sign({ Id: user._id }, process.env.SECRET_KEY, {
    expiresIn: "1h",
  });

  // Send reset token via email
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.PASS
    },
  });
  const mailOptions = {
    from: process.env.EMAIL,
    to: user.Email,
    subject: "Password Reset",
    html: `
    <p>Hi ${user.Name},</p>
<p>Use the following reset token to change your password: ${resetToken}</p>
<p>There was a request to change your password!</p>
<p>If you did not make this request, please ignore this email.</p>
<p>Otherwise, take the necessary steps to secure your account.</p>

    `,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log("Error sending email:", error);
      return res.status(500).json({ message: "Error sending email" });
    }
    console.log("Reset token email sent:", info.response);
    res.status(200).json({ message: "Password reset token sent", resetToken });
  });
});

router.post("/savepassword", async (req, res) => {
  const { NewPassword, resetToken } = req.body;
  

  try {
    const decoded = jwt.verify(resetToken,process.env.SECRET_KEY );

    const userId = decoded.Id;
    const user = await model.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashedNewPassword = await bcrypt.hash(NewPassword, 10);
    user.Password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.log("Error verifying reset token:", error);
    res.status(400).json({ message: "Invalid reset token" });
  }
});

router.post("/Changepassword", async (req, res) => {
  const { PreviousPassword, NewPassword } = req.body;

  // Check if the login token is present in the headers
  const loginToken = req.headers.authorization;
  console.log(loginToken)

  if (!loginToken) {
    return res.status(401).json({ message: "Unauthorized: Missing login token" });
  }

  try {
    const decoded = jwt.verify(loginToken, process.env.SECRET_KEY);

    const userId = decoded.id; // Assuming your login token has user id information
    const user = await model.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if the previous password matches the stored hashed password
    const passwordValidate = await bcrypt.compare(PreviousPassword, user.Password);

    if (!passwordValidate) {
      return res.status(401).json({ message: "Unauthorized: Incorrect previous password" });
    }

    // Hash and update the new password
    const hashedNewPassword = await bcrypt.hash(NewPassword, 10);
    user.Password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.log("Error verifying login token:", error);
    res.status(401).json({ message: "Unauthorized: Invalid login token" });
  }
});



router.get("/validuser", authenticate, async (req, res) => {
  try {
   
    const validUserOne = req.rootUser;
    res.status(200).json({ status: 200, validUserOne });
  } catch (error) {
    res.status(500).json({ status: 500, error: "Internal server error" });
  }
});

















module.exports = router;
