const express = require('express');
const passport = require('../middleware/passport');
const { forwardAuthenticated } = require('../middleware/checkAuth');

const router = express.Router();
router.get('/dog', (req, res) => {
	res.send('welcome');
});

// Github
router.get('/github', passport.authenticate('github', { scope: [ 'user:email' ] }));

router.get('/github/callback', passport.authenticate('github', { failureRedirect: '/login' }), function(req, res) {
	// Successful authentication, redirect home.
	res.redirect('/dashboard');
});

router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

router.post(
	'/login',
	passport.authenticate('local', {
		successRedirect: '/dashboard',
		failureRedirect: '/auth/login'
	})
);

router.get('/logout', (req, res) => {
	req.logout();
	res.redirect('/auth/login');
});

module.exports = router;
