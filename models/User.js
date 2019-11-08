const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const secret = require('../config').secret;

mongoose.plugin(schema => { schema.options.usePushEach = true });

const UserSchema = mongoose.Schema({
  username: { type: String, lowercase: true, unique: true, required: [true, "can't be blank."], match: [/^[a-zA-Z0-9_]+$/, "is invalid"], index: true },
  email: { type: String, lowercase: true, unique: true, required: [true, "can't be blank"], match: [/\S+@\S+\.\S+/, "is invalid"], index: true },
  bio: String, 
  image: String,
  hash: String,
  salt: String,
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Article' }]
}, { timestamps: true });

// validate for unique accounts
UserSchema.plugin(uniqueValidator, { message: "is already taken" });

// set up password hash for security
UserSchema.methods.setPassword = async function(password) {
  // this.salt = crypto.randomBytes(16).toString('hex');
  let hash = await new Promise((resolve, reject) => {
    crypto.pbkdf2(password, 'panda_rex', 10000, 512, 'sha512', (err, key) => {
      if (err) throw err;
      resolve(key.toString('hex'))
    });
  })
  return hash;
};
UserSchema.methods.validPassword = async function(password) {
  let hash = await new Promise((resolve, reject) => {
    crypto.pbkdf2(password, 'panda_rex', 10000, 512, 'sha512', (err, key) => {
      if (err) throw err;
      resolve(key.toString('hex'))
    });
  })
  return this.hash === hash;
};

// generate JWT tokens 
UserSchema.methods.generateJWT = function() {
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
UserSchema.methods.toAuthJSON = function() {
  return {
    username: this.username,
    email: this.email, 
    token: this.generateJWT(),
    bio: this.bio,
    image: this.image
  }
}

UserSchema.methods.toProfileJSONFor = function(user) {
  return {
    username: this.username,
    bio: this.bio,
    image: this.image || 'https://static.productionready.io/images/smiley-cyrus.jpg',
    following: false
  };
};

UserSchema.methods.favorite = function(id) {
  if (this.favorites.indexOf(id) === -1) {
    this.favorites = this.favorites.concat([id])
  }

  this.markModified('favorites');
  return this.save();
};

UserSchema.methods.unfavorite = function(id) {
  this.favorites.remove(id);
  return this.save();
};

UserSchema.methods.isFavorite = function(id) {
  return this.favorites.some(favoriteId => {
    return favoriteId.toString() === id.toString();
  })
}

mongoose.model('User',UserSchema);