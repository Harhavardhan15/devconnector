const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const config = require("config");
const jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");
const User = require("../../models/User");

//route POST api/users
//desc Register New User
//access Public
router.post(
  "/",
  [
    check("name", "Name is Required").not().isEmpty(),
    check("email", "Enter a valid Email").isEmail(),
    check(
      "password",
      "Please enter a password with minimum 6 characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    //console.log(req.body);
    const { name, email, password } = req.body;

    try {
      //see if user exists
      let user = await User.findOne({ email });
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }
      //getuser image from gravatar
      const avatar = gravatar.url(email, {
        s: "200",
        r: "pg",
        d: "mm",
      });

      user = new User({
        name,
        email,
        password,
        avatar,
      });
      //Encrypt Password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(user.password, salt);
      await user.save();
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
