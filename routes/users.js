var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
router.use(expressValidator());

var mongojs = require('mongojs');
var db = mongojs('passportapp', ['users']);

var bcrypt = require('bcryptjs');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;


//LOGIN PAGE - GET
router.get('/login', function(req, res){
    res.render('login');
});

//REGISTER PAGE - GET
router.get('/register', function(req, res){
    res.render('register');

});

//REGISTER PAGE - POST
router.post('/register', function(req, res){
    
    console.log("registering somebody");
    
    //GET FORM VALUES
    var name             = req.body.name;
    var email            = req.body.email;
    var username         = req.body.username;
    var password         = req.body.password;
    var password2        = req.body.password2;
    
    //VALIDATION
    
    req.checkBody('name', 'Name field is requiered').notEmpty();
    
    req.checkBody('email', 'Email field is requiered').notEmpty();
    req.checkBody('email', 'Enter a valid form of email').isEmail();
    
    req.checkBody('username', 'Username field is requiered').notEmpty();
    req.checkBody('password', 'Password field is requiered').notEmpty();
    req.checkBody('password2', 'Password Confirmation is required').notEmpty();
    req.checkBody('password2', 'Passwords must match').equals(req.body.password);
    
    //Check for erros 
    var errors = req.validationErrors();
    
    if(errors){
        
        console.log('FORM HAS ERRORS');
        //IF it works we want to render the next page sending the info
        res.render('register', {
            errors: errors,
            name: name,
            email: email,
            username: username,
            password: password,
            password2: password2,
            
        });
    }
    else{
        console.log('Success');
        
        //Creating a new object
        var newUser = {
            
            name: name,
            email: email,
            username: username,
            password: password,
        }
        
        //Encrypt password
        bcrypt.genSalt(10, function (err, salt){
            bcrypt.hash(newUser.password, salt, function(err, hash){
                //Encrypt the passport
                newUser.password = hash;
                
                
                //Insert the data into the databse
                db.users.insert(newUser, function (err, doc){
            if (err){
                res.send(err);
            }
            else{
                console.log('User Added!');
                
                //Success message
                req.flash('success', 'You have been registered! Now log in')
                
                //redirect after register
                res.location('/');
                res.redirect('/');
                    }
                });
            });
        });
        
        
        
        
    }
    
    

//END OF POST
});

//SERIALIAZER
passport.serializeUser(function(user, done) {
  done(null, user._id);
});

passport.deserializeUser(function(id, done) {
  db.users.findOne({_id: mongojs.ObjectId(id)}, function(err, user) {
      done(err, user); 
  });
});



//LOCAL STRATEGY
passport.use(new LocalStrategy(
    function(username, password, done){
        db.users.findOne({username: username}, function (err, user){
            
            if (err){
                return done(err);
            }
            
            if (!user){
                return done(null, false, {message: 'Incorrect Username'});
            }
            
        bcrypt.compare(password, user.password, function (err, isMatch){
            if (err){
                return done(err);
            }
            if(isMatch){
                return done(null, user);
            }
            else{
                return done(null, false, {message: 'Incorrect Username'});
            }
        });
            
        });
    }
    ));


//LOG IN - POST
router.post('/login',
  passport.authenticate('local', { successRedirect: '/',
                                   failureRedirect: '/users/login',
                                   failureFlash: 'Invalid Username or Paassword' }), 
                                 
                                    function(req,res){
                                       console.log('Auth Successful');
                                       res.redirect('/');
 });



//LOGOUT
router.get('/logout', function(req, res){
    req.logout();
    req.flash('success', 'You have logged out');
    res.redirect('/users/login');
});

//DO NOT ERASE
module.exports = router;



