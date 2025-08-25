const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Store for authorized PINs (in production, use a proper database)
const AUTHORIZED_PINS = new Map([
  // Add your PINs here - format: ['username', 'hashedPin']
  // Use addPin() function below to generate hashed PINs
  addPin('admin', '1234')
]);

// Helper function to add new PINs (run this to generate hashed PINs)
async function addPin(username, pin) {
  const hashedPin = await bcrypt.hash(pin.toString(), 10);
  AUTHORIZED_PINS.set(username, hashedPin);
  console.log(`Added PIN for ${username}: ${pin} (hashed)`);
}

// Uncomment and run these to add PINs (then comment them back out)
// addPin('admin', '1234');
// addPin('user1', '5678');
// addPin('demo', '9999');

// Session configuration
app.use(session({
  secret: 'RX1:M9WCG017CX0P====', // Change this in production
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting for login attempts
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const BLOCK_DURATION = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
  const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  
  // Reset attempts if block duration has passed
  if (now - attempts.lastAttempt > BLOCK_DURATION) {
    attempts.count = 0;
  }
  
  return {
    blocked: attempts.count >= MAX_ATTEMPTS && (now - attempts.lastAttempt) < BLOCK_DURATION,
    attempts: attempts.count,
    timeRemaining: Math.max(0, BLOCK_DURATION - (now - attempts.lastAttempt))
  };
}

function recordAttempt(ip, success = false) {
  if (success) {
    loginAttempts.delete(ip);
  } else {
    const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
    attempts.count++;
    attempts.lastAttempt = Date.now();
    loginAttempts.set(ip, attempts);
  }
}

// Middleware to check authentication
function requireAuth(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Serve static files only for authenticated users (except login page)
app.use((req, res, next) => {
  if (req.path === '/login' || req.path === '/api/login' || req.path === '/api/logout') {
    next();
  } else if (req.path.endsWith('.html') || req.path.endsWith('.js') || req.path.endsWith('.css')) {
    requireAuth(req, res, next);
  } else {
    next();
  }
});

// Serve static files from current directory
app.use(express.static('.', {
  index: false // Disable automatic index.html serving
}));

// Routes
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
  if (req.session.authenticated) {
    res.redirect('/');
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

app.post('/api/login', async (req, res) => {
  const { username, pin } = req.body;
  const clientIP = req.ip || req.connection.remoteAddress;
  
  // Check rate limiting
  const rateLimit = checkRateLimit(clientIP);
  if (rateLimit.blocked) {
    return res.json({
      success: false,
      message: 'Too many failed attempts. Try again later.',
      timeRemaining: Math.ceil(rateLimit.timeRemaining / 1000)
    });
  }
  
  // Validate input
  if (!username || !pin) {
    recordAttempt(clientIP);
    return res.json({
      success: false,
      message: 'Username and PIN are required'
    });
  }
  
  // Check if user exists and PIN is correct
  const storedHashedPin = AUTHORIZED_PINS.get(username);
  if (!storedHashedPin) {
    recordAttempt(clientIP);
    return res.json({
      success: false,
      message: 'Invalid credentials',
      attemptsRemaining: Math.max(0, MAX_ATTEMPTS - (rateLimit.attempts + 1))
    });
  }
  
  try {
    const pinMatch = await bcrypt.compare(pin.toString(), storedHashedPin);
    if (pinMatch) {
      recordAttempt(clientIP, true); // Reset attempts on success
      req.session.authenticated = true;
      req.session.username = username;
      req.session.loginTime = new Date().toISOString();
      
      res.json({
        success: true,
        message: 'Access granted',
        redirectUrl: '/52487234085885.html'
      });
    } else {
      recordAttempt(clientIP);
      res.json({
        success: false,
        message: 'Invalid credentials',
        attemptsRemaining: Math.max(0, MAX_ATTEMPTS - (rateLimit.attempts + 1))
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    recordAttempt(clientIP);
    res.json({
      success: false,
      message: 'Authentication error'
    });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      res.json({ success: false, message: 'Logout error' });
    } else {
      res.json({ success: true, redirectUrl: '/login' });
    }
  });
});

// API endpoint to check session status
app.get('/api/session', (req, res) => {
  if (req.session.authenticated) {
    res.json({
      authenticated: true,
      username: req.session.username,
      loginTime: req.session.loginTime
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Handle all other routes - redirect to login if not authenticated
app.get('*', requireAuth, (req, res) => {
  res.redirect('/');
});

// Admin function to add new PINs (call this when server is running)
app.post('/api/admin/add-pin', requireAuth, async (req, res) => {
  const { newUsername, newPin, adminPin } = req.body;
  
  // Simple admin verification (improve this for production)
  if (adminPin !== 'admin123') {
    return res.json({ success: false, message: 'Invalid admin PIN' });
  }
  
  try {
    await addPin(newUsername, newPin);
    res.json({ success: true, message: `PIN added for ${newUsername}` });
  } catch (error) {
    res.json({ success: false, message: 'Error adding PIN' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Renix MX1 Server running on port ${PORT}`);
  console.log(`Access the login page at: http://localhost:${PORT}/login`);
  console.log('\nAuthorized PINs:');
  for (const [username] of AUTHORIZED_PINS) {
    console.log(`- ${username}`);
  }
  
  if (AUTHORIZED_PINS.size === 0) {
    console.log('\n⚠️  No PINs configured! Uncomment the addPin() calls in the code to add some.');
  }
});