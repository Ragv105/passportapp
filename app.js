//DEPENDENCIES
var express = require('express');
var path = require('path');
var expressValidator = require('express-validator');
var session = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bodyParser = require('body-parser');
var flash = require('connect-flash');

//ROUTES//

var routes = require('./routes/index');
var users = require('./routes/users');

var app = express();

//View engine 
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

//Static Folder
app.use (express.static(path.join(__dirname, 'public')));
app.use('/css', express.static(__dirname + '/node_modules/bootstrap/dist/css'));


//Bodyparser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

//Express Session MiddleWare
app.use(session({
    secret: 'secret',
    saveUninitialized: true,
    resave: true
}));

//Passport MiddleWare
app.use(passport.initialize());
app.use(passport.session());

// Connect-Flash Middleware
app.use(flash());
app.use(function (req, res, next) {
  res.locals.messages = require('express-messages')(req, res);
  next();
});

app.get('*', function(req, res, next){
    res.locals.user = req.user || null; 
    next();
});

//Define routes
app.use('/', routes);
app.use('/users', users);

//LISTENER//
app.listen(process.env.PORT, process.env.IP, function(){
    console.log("SERVER CONNECTED");
});