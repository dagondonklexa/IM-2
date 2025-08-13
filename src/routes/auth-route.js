const express = require("express");
const router = express.Router();
const { register, login } = require("../controllers/auth-controller");

router.post("/register", register);
router.get("/login", login);

module.exports = router;
