//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const _ = require("lodash");     //working with arrays, numbers, objects, strings, etc.
const bcrypt = require('bcrypt');  //securety
const app = express();
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static("public"));

// parse incoming requests
//app.use(bodyParser.json());     // tells the system that you want json to be used.

mongoose.connect("mongodb://localhost:27017/testForAuth", {useUnifiedTopology:true , useNewUrlParser:true , useFindAndModify: false});

var db = mongoose.connection;

//Check connection
db.once('open', function() {
 console.log('Connected to mongoDB');
});
//Check for DB error
db.on('error', function(err) {
 console.log(err);});
 //_______________________________________________________________________________session

 //use sessions for tracking logins
 app.use(session({
   secret: 'work hard',
   resave: true,
   saveUninitialized: false,
   store: new MongoStore({
     mongooseConnection: db
   })
 }));
//_______________________________________________________________________________schema
// user email username password
var UserSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true,
    trim: true
  },
  username: {
    type: String,
    unique: true,
    required: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
  }
});

//__________________________________________________________________________________collection
//authenticate input against database
UserSchema.statics.authenticate = function (email, password, callback) {
  User.findOne({ email: email })
    .exec(function (err, user) {
      if (err) {
        return callback(err);
      } else if (!user) {
        err = new Error('User not found.');
        err.status = 401;
        return callback(err);
      }
      bcrypt.compare(password, user.password, function (err, result) {
        if (result === true) {
          return callback(null, user);
        } else {
          return callback();
        }
      });
    });
};

//hashing a password before saving it to the database
UserSchema.pre('save', function (next) {
  var user = this;
  bcrypt.hash(user.password, 10, function (err, hash) {
    if (err) {
      return next(err);
    }
    user.password = hash;
    next();
  });
});

//create collection
var User = mongoose.model('User', UserSchema);

//_______________________________________________________________________________routes main

// GET route for reading data
app.get('/', function (req, res, next) {
 res.sendFile(__dirname + '/login.html');
});

//_______________________________________________________________________________sign in
app.post('/login', function (req, res, next) {
if (req.body.logemail && req.body.logpassword) {
  User.authenticate(req.body.logemail, req.body.logpassword, function (error, user) {
    if (error || !user) {
      var err = new Error('Wrong email or password.');
      err.status = 401;
      return next(err);
    } else {
      req.session.userId = user._id;
      return res.redirect('/profile');
    }
  });
} else {
  var err1 = new Error('All fields required.');
  err1.status = 400;
  return next(err1);
}
});


//_______________________________________________________________________________sign up
app.post('/signup', function (req, res, next) {

  // confirm that user typed same password twice
  if (req.body.password !== req.body.passwordConf) {
    var err = new Error('Passwords do not match. :( ');
    err.status = 400;
    res.send("passwords dont match :.( ");
    return next(err);
  }
//if they all entered <sign up>
  if (req.body.email &&
    req.body.username &&
    req.body.password &&
    req.body.passwordConf) {

//create var to make doc
    var userData = {
      email: req.body.email,
      username: req.body.username,
      password: req.body.password,
    };

//create doc
    User.create(userData, function (error, user) {
      if (error) {
        return next(error);
      } else {
        req.session.userId = user._id;
        res.redirect('/profile');
      }
    });
  }

});
//_______________________________________________________________________________profile


// GET route after registering
app.get('/profile', function (req, res, next) {
  User.findById(req.session.userId)
    .exec(function (error, user) {
      if (error) {
        return next(error);
      } else {
        if (user === null) {
          var err = new Error('Not authorized! Go back!');
          err.status = 400;
          return next(err);
        } else {
          return res.render("profile" , {username: user.username , email:user.email}); //(/profile --> change url only) otherwise (render my ejs file)
        }
      }
    });
});

//_______________________________________________________________________________loguot

// GET for logout logout
app.get('/logout', function (req, res, next) {
  if (req.session) {
    // delete session object
    req.session.destroy(function (err) {
      if (err) {
        return next(err);
      } else {
        return res.redirect('/');
      }
    });
  }
});


//_______________________________________________________________________________

//_______________________________________________________________________________server port


    //server port
app.listen(3000, function() {
  console.log("Server started on port 3000");
});
