const express = require("express");
const connection = require("../connection");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const router = express.Router();

// commented because it is callback hell
// router.post("/signup", (req, res) => {
//   let user = req.body;
//   query = "select email,password,role,status from user where email=?";
//   connection.query(query, [user.email], (err, results) => {
//     if (!err) {
//       if (results.length <= 0) {
//         query =
//           "insert into user(name,contactNumber,email,password,status,role) values(?,?,?,?,'false','user')";
//         connection.query(
//           query,
//           [user.name, user.contactNumber, user.email, user.password],
//           (err, results) => {
//             if (!err) {
//               return res
//                 .status(200)
//                 .json({ message: "Successfully Registered" });
//             } else {
//               return res.status(500).json(err);
//             }
//           },
//         );
//       } else {
//         return res.status(400).json({ message: "Email already exist" });
//       }
//     } else {
//       return res.status(500).json(err);
//     }
//   });
// });

router.post("/signup", async (req, res) => {
  try {
    const user = req.body;
    const [results] = await connection
      .promise()
      .query("select email from user where email=?", [user.email]);
    if (results.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(user.password, saltRounds);
    await connection
      .promise()
      .query(
        "Insert into user(name,contactNumber,email,password,status,role) values(?,?,?,?,0,'user')",
        [user.name, user.contactNumber, user.email, hashedPassword],
      );
    return res.status(200).json({ message: "Successfully Registered" });
  } catch (err) {
    return res.status(500).json(err);
  }
});

router.post("/login", async (req, res) => {
  try {
    const user = req.body;
    const [results] = await connection
      .promise()
      .query("select email,password,role,status from user where email=?", [
        user.email,
      ]);

    if (results.length <= 0) {
      return res
        .status(401)
        .json({ message: "Incorrect username or password" });
    }
    const isMatch = await bcrypt.compare(user.password, results[0].password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "Incorrect username or password" });
    }
    if (results[0].status == 0) {
      return res.status(401).json({ message: "Wait for Admin Approval" });
    }
    const response = { email: results[0].email, role: results[0].role };
    const accessToken = jwt.sign(response, process.env.ACCESS_TOKEN, {
      expiresIn: "8h",
    });
    return res.status(200).json({ token: accessToken });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Something went wrong. Please try again later." });
  }
});

module.exports = router;
