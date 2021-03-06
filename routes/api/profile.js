const express = require("express");
const router = express.Router();
const auth = require("../../middleware/auth");
const Profile = require("../../models/Profile");
const User = require("../../models/User");
const { check, validationResult } = require("express-validator");

//route GET api/profile/me
//desc get current user profile
//access private
router.get("/me", auth, async (req, res) => {
  try {
    const profile = await Profile.findOne({
      user: req.user.id,
    }).populate("user", ["name", "avatar"]);
    if (!profile) {
      return res.status(400).json({ msg: "There is no profile for this user" });
    }
    res.json(profile);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error");
  }
});

//route POST api/profile
//desc Create or update user profile
//access private
router.post(
  "/",
  [
    auth,
    [
      check("status", "Status is required").not().isEmpty(),
      check("skills", "Skills is required").not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
    }
    // destructure the request
    const {
      company,
      website,
      location,
      bio,
      status,
      githubusername,
      skills,
      youtube,
      twitter,
      instagram,
      linkedin,
      facebook,
    } = req.body;
    //build profile object
    const profileFields = {};
    profileFields.user = req.user.id;
    if (company) profileFields.company = company;
    if (website) profileFields.website = website;
    if (location) profileFields.location = location;
    if (bio) profileFields.bio = bio;
    if (status) profileFields.status = status;
    if (githubusername) profileFields.githubusername = githubusername;
    if (skills) {
      profileFields.skills = skills.split(",").map((skill) => skill.trim());
    }
    //Build social object
    profileFields.social = {};
    if (youtube) profileFields.company = company;
    if (twitter) profileFields.twitter = twitter;
    if (facebook) profileFields.facebook = facebook;
    if (linkedin) profileFields.linkedin = linkedin;
    if (instagram) profileFields.instagram = instagram;
   
    try {
      let profile = await Profile.findOne({ user: req.user.id });
      if (profile) {
        //update profile
      
        profile = await Profile.findOneAndUpdate(
          { user: req.user.id },
          { $set: profileFields },
          { new: true }
        );
       
         return res.json(profile)
      }
     
      //create profile    
      profile = new Profile(profileFields);
       
   
      await profile.save();
      return res.json(profile);
    } 
    catch (error) {
      console.error(error.message);
      res.status(500).send("server error");
    }
  }
);

//route GET api/profile
//desc get all profiles
//access public
router.get('/',async (req,res)=>{
    try {
        const profiles = await Profile.find().populate('user',['name','avatar']);
        res.json(profiles);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

//route GET api/profile/user/user:id
//desc get  profile by id
//access public
router.get('/user/:user_id',async (req,res)=>{
    
    try {
        const profile = await Profile.findOne({user:req.params.user_id}).populate('user',['name','avatar']);
        if(!profile) return res.status(400).json({msg:'Profile not found'});

        res.json(profile);
    } catch (error) {
        console.error(error.message);
        if(error.kind == "ObjectId"){
            return res.status(400).json({ msg :'Profile not found'});
        }
        res.status(500).send('Server Error');
    }
}) ;



//route DELETE api/profile
//desc delete profile user and posts
//access Provate
router.delete('/',auth,async (req,res)=>{
  
    try {       
       //have to delete user posts

 //delete profile
 await Profile.findOneAndDelete({user:req.user.id});
 //delete user
 await User.findOneAndRemove({ _id: req.user.id })
        res.json({msg:"Delete Successful"});
    } catch (error) {
        console.error(error.message);
        if(error.kind == "ObjectId"){
            return res.status(400).json({ msg :'Profile not found'});
        }
        res.status(500).send('Server Error');
    }
}) ;

module.exports = router;
