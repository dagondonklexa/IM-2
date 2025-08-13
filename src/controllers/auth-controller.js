const User = require("../models/auth-model");
const bcrypt = require("bcryptjs");
const db = require("../config/db");

const register = async (req, res) => {
  const { name, email, password } = req.body;

  //   validation
  let errors = [];
  if (!name) errors.push({ field: name, message: "name is required" });
  if (!email) errors.push({ field: email, message: "email is required" });
  if (!password)
    errors.push({ field: password, message: "password is required" });

  if (errors.length > 0) return res.status(404).json(errors);

  try {
    const emailExists = await User.ifEmailExists(email);
    if (emailExists)
      return res.status(400).json({ message: "Email is already registered." });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    try {
      await User.createUser(name, email, hashedPassword);
    } catch (error) {
      console.log(error);
    }

    res.status(201).json({
      message: "User has been created successfully.",
    });
  } catch (error) {
    console.log(error);
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  const userDb = await db.query("SELECT * FROM user WHERE email = ?", [email]);

  if(userDb.length === 0){
    return res.status(401).json({ message: "User Not Found" });
  }

  const { name, email: dbEmail, password: dbPassword } = userDb[0];
  
  const isMatch = await bcrypt.compare(password, dbPassword);
  if(!isMatch){
    return res.status(401).json({ message: "Invalid Password" });
  }

  res.json({
    message: "Login Successfull",
    data: {
        greeting: "Hello User",
        name,
        email: dbEmail
    }
  });
};

module.exports = { register, login };
