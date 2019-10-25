const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const secret = require('../config').secret;

const UserSchema = mongoose.Schema({
  username: { type: String, lowercase: true, unique: true, required: [true, "can't be blank."], match: [/^[a-zA-Z0-9]+$/, "is invalid"], index: true },
  email: { type: String, lowercase: true, unique: true, required: [true, "can't be blank"], match: [/\S+@\S+\.\S+/, "is invalid"], index: true },
  bio: String, 
  image: String,
  hash: String,
  salt: String
}, { timestamps: true });

// validate for unique accounts
UserSchema.plugin(uniqueValidator, { message: "is already taken" });

// set up password hash for security
UserSchema.methods.setPassword = (password) => {
  this.salt = crypto.randomBytes(16).toString('hex');
  this.hash = crypto.pbkdf2(password, this.salt, 10000, 512, 'sha512').toString('hex');
};
UserSchema.methods.validPassword = (password) => {
  const hash = crypto.pbkdf2(password, this.salt, 10000, 512, 'sha512').toString('hex');
  return this.hash === hash;
};

// generate JWT tokens 
UserSchema.methods.generateJWT = () => {
  const today = new Date();
  const expiry = new Date(today);
  expiry.setDate(today.getDate() + 60);

  return jwt.sign({
    id: this._id,
    exp: parseInt(expiry.getTime() / 1000),
    username: this.username
  }, secret);
};

// only authenticated users can access their information
UserSchema.methods.toAuthJSON = () => {
  return {
    username: this.username,
    email: this.email, 
    token: this.generateJWT(),
    bio: this.bio,
    image: this.image
  }
}

mongoose.model('User',UserSchema);