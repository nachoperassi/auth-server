'use strict';

const passport = require('passport');

/**
 * Render the login.ejs
 * @param   {Object} req - The request
 * @param   {Object} res - The response
 */
exports.loginForm = (req, res) => {
  res.render('login');
};

/**
 * Authenticate normal login page using local strategy
 */
exports.login = [
  passport.authenticate('local', { successReturnToOrRedirect: '/', failureRedirect: '/login' }),
];

/**
 * Logout of the system and redirect to root
 * @param   {Object}   req - The request
 * @param   {Object}   res - The response
 */
exports.logout = (req, res) => {
  req.logout();
  res.redirect('/');
};
