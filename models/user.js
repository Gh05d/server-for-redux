const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs');
const Schema = mongoose.Schema;

// Define the model
const userSchema = new Schema({
 email: { type: String, unique: true, lowercase: true }, // check whether the
 password: String                                        // email is unique
})

// On Save Hook, encrypt password
// pre = before saving, run the function
userSchema.pre('save', function(next) {
 const user = this; // the email and password the user enters

 // Generate a salt, then run callback
 bcrypt.genSalt(10, function(err, salt) {
  if (err) { return next(err); }

  // Encrypt the password using the created salt
  bcrypt.hash(user.password, salt, null, function(err, hash) {
   if (err) { return next(err); }

   // Replace password with encrypted one
   user.password = hash;
   next();
  });
 });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) { return callback(err) }

    callback(null, isMatch);
  });
}

// Create the model class
const ModelClass = mongoose.model('user', userSchema); // class of users

// Export the model
module.exports = ModelClass;
