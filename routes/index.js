var express = require('express');
var router = express.Router();

router.get('/', ensureAuthenticated, function(request, response){
	response.render('index');
});

function ensureAuthenticated(req, res, next){
	if(req.isAuthenticated()){
		return next();
	} else {
		res.redirect('/users/login');
	}
}

module.exports = router;