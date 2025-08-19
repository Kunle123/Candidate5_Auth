const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Strategy: OIDCStrategy } = require('passport-openidconnect');
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

// Add OIDC strategy for LinkedIn
passport.use('linkedin-oidc', new OIDCStrategy({
  issuer: 'https://www.linkedin.com',
  authorizationURL: 'https://www.linkedin.com/oauth/v2/authorization',
  tokenURL: 'https://www.linkedin.com/oauth/v2/accessToken',
  userInfoURL: 'https://api.linkedin.com/v2/userinfo',
  clientID: process.env.LINKEDIN_CLIENT_ID,
  clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
  callbackURL: 'https://candidatev-auth-production.up.railway.app/auth/linkedin/callback',
  scope: ['openid', 'profile', 'email']
}, async (issuer, sub, profile, jwtClaims, accessToken, refreshToken, params, done) => {
  console.log('--- LinkedIn OIDC callback START ---');
  try {
    console.log('OIDC LinkedIn callback:', {
      issuer, sub, profile, jwtClaims, accessToken, refreshToken, params
    });
    if (!accessToken) {
      console.error('No access token received from LinkedIn');
      console.log('--- LinkedIn OIDC callback END (error: no access token) ---');
      return done(new Error('No access token received from LinkedIn'), null);
    }
    let email = profile.email || (jwtClaims && jwtClaims.email) || null;
    let name = profile.displayName || profile.name || (jwtClaims && jwtClaims.name) || '';
    if (!email) {
      console.warn('No email found in LinkedIn OIDC profile or claims');
    }
    let user = null;
    if (email) {
      user = await User.findOne({ where: { email } });
      console.log('User lookup by email:', email, user ? 'FOUND' : 'NOT FOUND');
    }
    if (!user) {
      user = await User.create({
        email: email || null,
        name: name,
        linkedin: sub,
        profile: profile
      });
      console.log('Created new user from LinkedIn OIDC:', user.id);
    } else {
      if (!user.linkedin) user.linkedin = sub;
      if (!user.name && name) user.name = name;
      await user.save();
      console.log('Found existing user for LinkedIn OIDC:', user.id);
    }
    // Always create user profile in user service (via API gateway)
    try {
      const userProfile = {
        id: user.id,
        email: user.email,
        name: user.name || ''
      };
      console.log('Creating user profile in user service:', userProfile);
      const response = await fetch('https://api-gw-production.up.railway.app/api/user/profile', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.INTER_SERVICE_SECRET}`
        },
        body: JSON.stringify(userProfile),
        timeout: 10000 // 10 second timeout
      });
      const responseBody = await response.text();
      console.log('User service profile creation response:', response.status, responseBody);
      if (!response.ok) {
        console.error('Failed to create user profile (LinkedIn OIDC):', responseBody);
        console.log('--- LinkedIn OIDC callback END (error: user service profile creation failed) ---');
        return done(new Error('Failed to create user profile in user service'), null);
      }
    } catch (profileError) {
      console.error('Error creating user profile (LinkedIn OIDC):', profileError);
      console.log('--- LinkedIn OIDC callback END (error: user service profile creation exception) ---');
      return done(new Error('Error creating user profile in user service'), null);
    }
    console.log('--- LinkedIn OIDC callback END (success) ---');
    return done(null, {
      id: user.id,
      email: user.email,
      name: user.name,
      provider: 'linkedin',
      accessToken
    });
  } catch (error) {
    console.error('LinkedIn OIDC strategy error:', error);
    console.log('--- LinkedIn OIDC callback END (error: general exception) ---');
    return done(error, null);
  }
}));
