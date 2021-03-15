const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GithubStrategy = require('passport-github2').Strategy;
const userController = require("../controllers/userController");
const dotenv = require('dotenv');
dotenv.config();

const localLogin = new LocalStrategy(
  {
    usernameField: "email",
    passwordField: "password",
  },
  (email, password, done) => {
    const user = userController.getUserByEmailIdAndPassword(email, password);
    return user
      ? done(null, user)
      : done(null, false, {
          message: "Your login details are not valid. Please try again",
        });
  }
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  let user = userController.getUserById(id);
  if (user) {
    done(null, user);
  } else {
    done({ message: "User not found" }, null);
  }
});

passport.use(new GithubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: 'http://localhost:8000/auth/github/callback'
},
function(accessToken, refreshToken, profile, done) {
  userController.addUser(profile);
  return done(null, profile);
}))


module.exports = passport.use(localLogin);
