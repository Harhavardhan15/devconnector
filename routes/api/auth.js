const express = require('express'); 
const router = express.Router();
const auth = require("../../middleware/auth");
const User = require("../../models/User")
const bcrypt = require("bcryptjs");
const config = require("config");
const jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");
//route GET api/auth
//desc test route
//access private
router.get('/', auth ,async (req,res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
})

//route POST api/auth
//desc Authenticate User get token
//access Public
router.post(
    "/",
    [
      check("email", "Enter a valid Email").isEmail(),
      check(
        "password",
        "Password is required").exists() 
    ],
    async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      //console.log(req.body);
      const {  email, password } = req.body;
  
      try {
        //see if user exists
        let user = await User.findOne({ email });
        if (!user) {
          return res
            .status(400)
            .json({ errors: [{ msg: "User does not exist" }] });
        }
    //match password
    const isMatch = await bcrypt.compare(password,user.password);
    if(!isMatch){
        return res
        .status(400)
        .json({ errors: [{ msg: "Invalid password" }] });
    }

        //Return json web token
        const payload = {
          user: {
            id: user.id,
          },
        };
  
        await jwt.sign(
          payload,
          config.get("jwtSecret"),
          { expiresIn: 360000 },
          (err, token) => {
            if (err) throw err;
           return  res.json({ token });
          }
        );
  
        // return  res.send("Users Registered Successfully");
      } catch (error) {
        console.error(error.message);
        return res.status(500).send("server error");
      }
    }
  );

module.exports = router;