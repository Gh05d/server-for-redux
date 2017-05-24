const jwt  = require('jwt-simple');
const config = require('../config');
const User = require('../models/user');

// Encrypt the ID, not the email as it can change
function tokenForUser(user) {
  const timestamp = new Date().getTime();
  // sub = subject, iat = issued at time
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  //User gets a token for the authenticated email and password
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
 const email = req.body.email;
 const password = req.body.password;

 if (!email || !password) {
   return res.status(422).send({ error: 'Email or password missing!'});
 }

 // Check whether user with a given email exists
 User.findOne({ email: email }, function(err, existingUser) {
  if (err) { return next(err); }

  // If Email already exists, return an Error
  if (existingUser) {
   return res.status(422).send({ error: 'Email is in use' });
  }

  // If Email doesn't exist, create and serve user record
  const user = new User({
   email: email,
   password: password
  });

  user.save(function(err) {
   if (err) { return next(err); }

   // Respond with a token
   res.json({ token: tokenForUser(user) });
  });
 });
}
