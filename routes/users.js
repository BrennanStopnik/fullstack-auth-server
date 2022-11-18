var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { uuid } = require('uuidv4');
const { db } = require('../mongo.js');


/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post("/register", async (req, res, next) => {
  try { 
    const email = req.body.email;
    const password = req.body.password;

    const saltRounds = 5;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashPword = await bcrypt.hash(password, salt);

    user = {
      email: email,
      password: hashPword,
      id: uuid()
    };

    const result = await db().collection("users").insertOne(user);

    res.json({
      success: true,
      message: "User created",
      result
    })

  } catch (err) {
    res.json({
      success: false,
      error: err.toString()
    });
  }
})

router.post("/login", async (req, res, next) => {
  try { 
    const email = req.body.email;
    const password = req.body.password;
    const user = await db().collection("users").findOne({ email });

    if (!user) {
      res.json({
        success: false,
        message: "User not found"
      }).status(204);
      return;
    }

    const hashedUserPword = user.password;

    const isPasswordCorrect = await bcrypt.compare(password, hashedUserPword);

    if (!isPasswordCorrect) {
      res.json({
        success: false,
        message: "Incorrect password"
      });
      return;
    }

    const permish = email.includes("@codeimmersives.com") ? "admin" : "user";

    const userData = { 
      date: new Date(),
      id: user.id,
      scope: permish
    };

    const theKey = process.env.JWT_SECRET_KEY;

    const exp = Math.floor(Date.now() / 1000) + (60 * 60);

    const payload = {
      userData,
      exp
    };

    const token = jwt.sign(payload, theKey);

    res.json({
      success: true,
      message: "Authentication successful!",
      token,
      email
    });    
  } catch (err) {
    res.json({
      success: false,
      message: err.message
    });
  }
})

router.get("/message", (req, res, next) => {
  const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
  const token = req.header(tokenHeaderKey);
  const theKey = process.env.JWT_SECRET_KEY;
  try {
    const verified = jwt.verify(token, theKey);

    if (!verified) {
      return res.json({
        success: false,
        message: "ID Token could not be verified",
      });
    }
    if (verified.userData.scope === "admin") {
      res.json({
        success: true,
        message: "You are an admin",
        verified
      });
    }
    if (verified.userData.scope === "user") {
      res.json({
        success: true,
        message: "You are a user",
        verified
      });
    }

    throw Error("Access Denied");
  } catch (err) {
    res.json({
      success: false,
      message: err.message
    });
  }
})

module.exports = router;
