const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const User = require('../../models/User');
const fetch = require('node-fetch');

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
    scope: ['openid', 'profile', 'email'],
    passReqToCallback: true
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      // Fetch user info from OIDC /userinfo endpoint
      const userinfoRes = await fetch('https://api.linkedin.com/v2/userinfo', {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      if (!userinfoRes.ok) {
        const errText = await userinfoRes.text();
        console.error('LinkedIn OIDC /userinfo error:', errText);
        return done(new Error('Failed to fetch LinkedIn OIDC userinfo'), null);
      }
      const userinfo = await userinfoRes.json();
      console.log('LinkedIn OIDC userinfo:', JSON.stringify(userinfo, null, 2));
      let email = userinfo.email ? userinfo.email.toLowerCase() : null;
      let user = null;
      if (email) {
        user = await User.findOne({ where: { email } });
      }
      if (!user) {
        // Try to find by LinkedIn sub (OIDC subject) if email not found
        user = await User.findOne({ where: { linkedin: userinfo.sub } });
      }
      if (user) {
        // Link LinkedIn account if not already linked
        if (!user.linkedin) {
          user.linkedin = userinfo.sub;
          await user.save();
        }
      } else {
        // Create new user
        user = await User.create({
          email: email || null,
          name: userinfo.name || '',
          linkedin: userinfo.sub,
          profile: userinfo,
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
      console.error('LinkedIn OIDC strategy error:', error);
      return done(error, null);
    }
  }
));
