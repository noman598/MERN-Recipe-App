import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const router = express.Router();
import { UserModel } from "../models/Users.js";

router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const user = await UserModel.findOne({ username }); //Find username in database.
  if (user) {       //check wheather username already exist or not
    return res.status(400).json({ message: "Username already exists" });
  }
  const hashedPassword = await bcrypt.hash(password, 10); // hashed password
  const newUser = new UserModel({ username, password: hashedPassword }); //sending hashed password with username to database for store
  await newUser.save(); 
  res.json({ message: "User registered successfully" });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await UserModel.findOne({ username }); //check username in db

  if (!user) { //check user exist or not
    return res
      .status(400)
      .json({ message: "Username or password is incorrect" });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password); //Input password is converted to hash and check with stored hashing password
  if (!isPasswordValid) {  //check equality
    return res
      .status(400)
      .json({ message: "Username or password is incorrect" });
  }
  const token = jwt.sign({ id: user._id }, "secret"); // creating token for user
  res.json({ token, userID: user._id });
});

export { router as userRouter };

// varifying the token - 
// Upon receiving a request with the token, the server needs to verify 
// its authenticity and integrity to ensure it has not been tampered with or forged.
// Decoding the Token - 
// 1) extract the information from the token's payload
// 2)Signature Verification:
// 3)Checking Expiration and Other Claims:
// 4)Handling Invalid Tokens: 401 or 403 
export const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    jwt.verify(authHeader, "secret", (err) => {
      if (err) {
        return res.sendStatus(403);
      }
      next();
    });
  } else {
    res.sendStatus(401);
  }
};
