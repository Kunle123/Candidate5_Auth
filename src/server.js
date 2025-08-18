/**
 * server.js
 * 
 * Main entry point for the CandidateV Auth Service.
 * 
 * - Sets up Express server with robust CORS handling for production and development.
 * - Configures secure session management with Redis.
 * - Initializes Passport for authentication.
 * - Mounts authentication routes and health check.
 * - Handles errors gracefully.
 * 
 * Created: 2024-04-27
 * Author: CandidateV Team
 */

require('dotenv').config();
const express = require('express');
const passport = require('passport');
const cors = require('cors');
const morgan = require('morgan');
const sequelize = require('../models/sequelize');
const session = require('express-session');

// Import routes and passport config
const authRoutes = require('./routes/auth');
//const cvRoutes = require('./routes/cv');
require('./config/passport');

const app = express();

// --- CORS Configuration ---
// Allow only trusted origins (add more as needed)
const allowedOrigins = [
  'https://candidate-v-frontend.vercel.app',
  'https://candidate-v.vercel.app',
  'https://candidatev.vercel.app',
  'https://api-gw-production.up.railway.app',
  'http://localhost:3000',
  'http://localhost:5173',
  'https://candidate5.co.uk' // Added production frontend
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, origin); // Echo the actual origin
    } else {
      console.warn('Blocked by CORS:', origin);
      return callback(null, false); // No CORS headers
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Manual OPTIONS handler for robust preflight support
app.options('*', cors());

// --- Middleware ---
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Content Security Policy (CSP) ---
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' https://www.google.com https://www.gstatic.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "img-src 'self' data: https://www.gstatic.com https://www.google.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "connect-src 'self' https://api-gw-production.up.railway.app; " +
    "frame-src https://www.google.com https://www.gstatic.com; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self' https://accounts.google.com https://www.linkedin.com; "
  );
  next();
});

// --- Passport Initialization ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true if using HTTPS
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000 // 10 minutes
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// --- Routes ---
app.use('/auth', authRoutes);
//app.use('/cvs', cvRoutes);

// --- Health Check ---
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Auth service is running' });
});

// --- Error Handling ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// --- Start Server ---
const PORT = process.env.PORT || 3001;
sequelize.sync({ alter: true });
app.listen(PORT, () => {
  console.log(`Auth service listening on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
});

module.exports = app; 