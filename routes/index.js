var express = require('express');
var router = express.Router();

router.get('/',ensureAuthenticated, function(req, res){
    res.render('index');
});

//Checks authentiction of users.
function ensureAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next()
    }
    res.redirect('/users/login');
}


//NEVER TAKE OUT
module.exports = router;