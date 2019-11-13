const mongoose = require('mongoose');
const router = require('express').Router();
const passport = require('passport');
const User = mongoose.model('User');
const auth = require('../auth');

router.post('/users', (req, res, next) => {
  let user = new User();

  user.username = req.body.user.username;
  user.email = req.body.user.email;
  user.setPassword(req.body.user.password);

  user.save().then(() => {
    return res.json({ user: user.toAuthJSON() });
  })
  .catch(next);
});

router.post('/users/login', (req, res, next) => {
  if (!req.body.user.email) {
    return res.status(422).json({ error: { email: "can't be blank" } });
  }

  if (!req.body.user.password) {
    return res.status(422).json({ error: { password: "can't be blank" } });
  }

  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    };

    if (user) {
      console.log("==|==|> user:",user)
      token = user.generateJWT();
      return res.json({ user: user.toAuthJSON(), token });
    } else {
      return res.status(422).json(info);
    }
  })(req, res, next);
});

router.get('/user', auth.required, (req, res, next) => {
  User.findById(req.payload.id).then(user => {
    if (!user) {
      return res.sendStatus(401);
    }

    return res.json({ user: user.toAuthJSON() });
  })
  .catch(next);
});

router.put('/user', auth.required, (req, res, next) => {
  User.findById(req.payload.id).then(async user => {
    if (!user) {
      return res.sendStatus(401);
    }

    if (typeof req.body.user.email !== 'undefined') {
      user.email = req.body.user.email;
    }
    if (typeof req.body.user.username !== 'undefined') {
      user.username = req.body.user.username;
    }
    if (typeof req.body.user.bio !== 'undefined') {
      user.bio = req.body.user.bio;
    }
    if (typeof req.body.user.image !== 'undefined') {
      user.image = req.body.user.image;
    }
    if (typeof req.body.user.password !== 'undefined') {
      let newPass = await user.setPassword(req.body.user.password);
      user.hash = newPass;
    }

    return user.save().then(() => {
      return res.json({ user: user.toAuthJSON() });
    });
  })
  .catch(next);
});

module.exports = router;