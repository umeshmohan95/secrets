//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs=require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
// const md5 = require('md5');
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
console.log(process.env.SECRET);

app.use(bodyParser.urlencoded({extended:true}));
app.set('view engine','ejs');
app.use(express.static('public'));

app.use(session({
  secret: "our litle secret.",
  resave: false,
  saveUninitialized:false
}));

//passport session related code placement is important
app.use(passport.initialize());   //to initialize passport
app.use(passport.session());      //to use passport to manage our sessions


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //https://github.com/jaredhanson/passport-google-oauth2/pull/51
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

mongoose.connect("mongodb://localhost:27017/userDB", {useUnifiedTopology: true, useNewUrlParser: true, useCreateIndex: true });

///////////////Login details collection ////////////////////////

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);   //setup userSchema to use localMongoose asplugin
userSchema.plugin(findOrCreate);      //for Google OAuth

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());      //using passport to create a local mongoose statergy

// passport.serializeUser(User.serializeUser());       //
// passport.deserializeUser(User.deserializeUser());   //serialize and deserializeUser (destroy cookies)
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

///////////////Login details collection ////////////////////////
const secretSchema = new mongoose.Schema({
  secret: String
});

const Message = mongoose.model("message",userSchema);
//////////////////////////////////////////////////////////


///////////////////////////////////////////get requests//////////////////////////////////////////////
app.get("/", function(req,res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/register", function(req,res){
  res.render("register");
});

app.get("/login", function(req,res){
  res.render("login");
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else(res.redirect("/login"));
});

//creating secret route to check automatically whether user is still logged in or not
app.get("/secrets", function(req,res){
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }else(res.redirect("/login"));
  // console.log(req.user.id); //5fa69e31add7484a54780b06

  if(req.isAuthenticated()){
  User.find({"secret":{$ne:  null}}, function(err, foundUsers){
  // User.find({"_id":"9e31add7484a54780b06"}, function(err, foundUsers){

    if (err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
  }else(res.redirect("/login"));
});

app.get("/logout", function(req,res){
  req.logout();
  res.redirect('/');
});

////////////////////////////////////POST request //////////////////////////////////////////////

app.post("/register", function(req,res){
//using passport-local-mongoose

User.register({username: req.body.username}, req.body.password, function(err, user){
  if(err){
    console.log(err);
    res.redirect("/register");
  }else{
    passport.authenticate("local")(req,res, function(){    //authenticating our user using passport locally
      res.redirect("/secrets");
    });
  }
});

});

app.post("/login",function(req,res){
//using passport-local-mongoose package
//http://www.passportjs.org/docs/login/
const user = new User({
  username: req.body.username,
  password: req.body.password
});
req.login(user, function(err){
  if(err){
    console.log(err);
  }else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("secrets");
    });
  }
})
});

app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;
  // console.log(req.user);

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save(function(){
            res.redirect("/secrets");
        });
      }
    }
  });

  // const newMessage = new Message({
  //   secret: req.body.secret
  // });
  //
  // console.log(req.body.secret);
  //
  // newMessage.save(function(err){
  //   if(!err){
  //     res.send("Successfully submitted message")
  //   }else{console.log(err);}
  // })
});


app.listen(3000, function(){
  console.log("Successfully connected");
});
