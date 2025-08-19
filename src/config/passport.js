const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const User = require('../../models/User');

// Serialize user for the session
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user from the session
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://candidatev-auth-production.up.railway.app/auth/google/callback",
    passReqToCallback: true
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails && profile.emails[0] && profile.emails[0].value ? profile.emails[0].value.toLowerCase() : null;
      if (!email) {
        return done(new Error('No email found in Google profile'), null);
      }
      let user = await User.findOne({ where: { email } });
      if (user) {
        // Link Google account if not already linked
        if (!user.google) {
          user.google = profile.id;
          await user.save();
        }
      } else {
        // Create new user
        user = await User.create({
          email,
          name: profile.displayName,
          google: profile.id,
          profile: profile._json || {},
        });
      }
      return done(null, {
        id: user.id,
        email: user.email,
        name: user.name,
        provider: 'google',
        accessToken
      });
    } catch (error) {
      return done(error, null);
    }
  }
));

// LinkedIn Strategy
passport.use(new LinkedInStrategy({
    clientID: process.env.LINKEDIN_CLIENT_ID,
    clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
    callbackURL: 'https://candidatev-auth-production.up.railway.app/auth/linkedin/callback',
    scope: ['r_liteprofile', 'openid', 'profile'],
    passReqToCallback: true
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      console.log('LinkedIn profile:', JSON.stringify(profile, null, 2));
      // LinkedIn may not provide email unless scope is granted
      let email = null;
      if (profile.emails && profile.emails.length > 0) {
        email = profile.emails[0].value.toLowerCase();
      }
      let user = null;
      if (email) {
        user = await User.findOne({ where: { email } });
      }
      if (!user) {
        // Try to find by LinkedIn ID if email not found
        user = await User.findOne({ where: { linkedin: profile.id } });
      }
      if (user) {
        // Link LinkedIn account if not already linked
        if (!user.linkedin) {
          user.linkedin = profile.id;
          await user.save();
        }
      } else {
        // Create new user
        user = await User.create({
          email: email || null,
          name: profile.displayName,
          linkedin: profile.id,
          profile: profile._json || {},
        });
      }
      return done(null, {
        id: user.id,
        email: user.email,
        name: user.name,
        provider: 'linkedin',
        accessToken
      });
    } catch (error) {
      console.error('LinkedIn strategy error:', error);
      return done(error, null);
    }
  }
));
