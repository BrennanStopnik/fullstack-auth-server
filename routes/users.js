var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { uuid } = require('uuidv4');


/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post("/registration", async (req, res, next) => {
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

    const hashedUserPassword = user.password;

    const isPasswordCorrect = await bcrypt.compare(password, hashedUserPassword);

    if (!isPasswordCorrect) {
      res.json({
        success: false,
        error: "Incorrect password"
      });
      return;
    }

    const exp = Math.floor(Date.now() / 1000) + (60 * 60);

    const payload = {
      email,
      exp,
      scope: "user"
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({
      success: true,
      message: "Authentication successful!",
      token
    });    
  } catch (err) {
    res.json({
      success: false,
      message: err.message
    });
  }
})

router.get("/message", (req, res, next) => {
  try {
    const token = req.header("ci-token");
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    console.log(verified);

  } catch (err) {
    res.json({
      success: false,
      message: err.message
    });
  }
})


module.exports = router;
