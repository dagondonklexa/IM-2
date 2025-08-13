const express = require("express");
const app = express();
const { createUserTable } = require("./models/auth-model");

createUserTable()
  .then(() => console.log("Table user has been created"))
  .catch((error) => console.log(error));

app.use(express.json());

app.use("/api/auth", require("./routes/auth-route"));

app.listen(5000, () => {
  console.log("Server Running");
});
