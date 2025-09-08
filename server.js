const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const https = require('https');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_SECRET_LENGTH = parseInt(process.env.MAX_SECRET_LENGTH) || 50000;

// Password generator configuration
const DEFAULT_PASSWORD_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
const PASSWORD_INCLUDE_CHARS = process.env.PASSWORD_INCLUDE_CHARS || DEFAULT_PASSWORD_CHARS;
const PASSWORD_EXCLUDE_CHARS = process.env.PASSWORD_EXCLUDE_CHARS || '';
const PASSPHRASE_SEPARATOR = process.env.PASSPHRASE_SEPARATOR || '-';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcElem: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : true,
  credentials: false
}));

app.use(express.json({ limit: '10mb' }));

// Explicitly serve crypto-utils.js with correct MIME type
app.get('/crypto-utils.js', (req, res) => {
  res.setHeader('Content-Type', 'text/javascript');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'public', 'crypto-utils.js'));
});

app.use(express.static('public'));

const createLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.CREATE_RATE_LIMIT) || 10, // limit each IP to 10 requests per windowMs
  message: { error: 'Too many secrets created, try again later' }
});

const retrieveLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.RETRIEVE_RATE_LIMIT) || 50, // limit each IP to 50 requests per windowMs
  message: { error: 'Too many retrieval attempts, try again later' }
});

const secrets = new Map();

function generateSecureId() {
  return crypto.randomBytes(32).toString('base64url');
}

// Password generator functions
function generatePassword(length = 16) {
  let chars = PASSWORD_INCLUDE_CHARS;
  
  // Remove excluded characters
  if (PASSWORD_EXCLUDE_CHARS) {
    for (const char of PASSWORD_EXCLUDE_CHARS) {
      chars = chars.replace(new RegExp(`\\${char}`, 'g'), '');
    }
  }
  
  if (chars.length === 0) {
    throw new Error('No valid characters available for password generation');
  }
  
  let password = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = crypto.randomInt(0, chars.length);
    password += chars[randomIndex];
  }
  
  return password;
}

function generatePassphrase(wordCount = 4, separator = null) {
  // Common word list for passphrases
  const words = [
    'apple', 'brave', 'chair', 'dance', 'eagle', 'flame', 'grace', 'house',
    'image', 'juice', 'knife', 'light', 'mouse', 'nurse', 'ocean', 'piano',
    'quiet', 'river', 'smile', 'table', 'uncle', 'voice', 'water', 'xerus',
    'young', 'zebra', 'angel', 'bread', 'cloud', 'dream', 'earth', 'focus',
    'giant', 'happy', 'index', 'joint', 'knock', 'laugh', 'magic', 'night',
    'olive', 'peace', 'quest', 'radio', 'sugar', 'tower', 'unite', 'value',
    'white', 'extra', 'yield', 'zesty', 'amber', 'beach', 'climb', 'depth',
    'event', 'frost', 'group', 'heart', 'ideal', 'judge', 'karma', 'logic',
    'merit', 'noble', 'orbit', 'power', 'quick', 'royal', 'spark', 'trust',
    'urban', 'vivid', 'world', 'xenon', 'yacht', 'zones'
  ];
  
  const usedSeparator = separator || PASSPHRASE_SEPARATOR;
  let passphrase = [];
  
  for (let i = 0; i < wordCount; i++) {
    const randomIndex = crypto.randomInt(0, words.length);
    const word = words[randomIndex];
    // Capitalize first letter of each word
    const capitalizedWord = word.charAt(0).toUpperCase() + word.slice(1);
    passphrase.push(capitalizedWord);
  }
  
  return passphrase.join(usedSeparator);
}

function cleanupExpired() {
  const now = Date.now();
  for (const [id, secret] of secrets.entries()) {
    if (secret.expiresAt && now > secret.expiresAt) {
      secrets.delete(id);
    }
  }
}

setInterval(cleanupExpired, 60000); // Clean up every minute

app.post('/api/store', createLimiter, (req, res) => {
  try {
    const { encryptedData, iv, expirationMinutes } = req.body;
    
    if (!encryptedData || !iv || !expirationMinutes) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (typeof encryptedData !== 'string' || typeof iv !== 'string') {
      return res.status(400).json({ error: 'Invalid data format' });
    }
    
    // Validate encrypted data length (approximate check for original text length)
    if (encryptedData.length > MAX_SECRET_LENGTH * 2) { // Base64 encoding roughly doubles size
      return res.status(400).json({ error: `Secret too long (max ${MAX_SECRET_LENGTH} characters)` });
    }
    
    const expiration = parseInt(expirationMinutes);
    if (isNaN(expiration) || expiration < 1 || expiration > 10080) { // max 7 days
      return res.status(400).json({ error: 'Invalid expiration time' });
    }
    
    const id = generateSecureId();
    const expiresAt = Date.now() + (expiration * 60 * 1000);
    
    secrets.set(id, {
      encryptedData,
      iv,
      expiresAt,
      accessed: false
    });
    
    res.json({ 
      id,
      expiresAt: new Date(expiresAt).toISOString()
    });
    
  } catch (error) {
    console.error('Store error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/retrieve/:id', retrieveLimiter, (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id || typeof id !== 'string') {
      return res.status(400).json({ error: 'Invalid ID' });
    }
    
    const secret = secrets.get(id);
    
    if (!secret) {
      return res.status(404).json({ error: 'Secret not found or expired' });
    }
    
    if (secret.accessed) {
      secrets.delete(id);
      return res.status(404).json({ error: 'Secret has already been accessed' });
    }
    
    if (Date.now() > secret.expiresAt) {
      secrets.delete(id);
      return res.status(404).json({ error: 'Secret has expired' });
    }
    
    secret.accessed = true;
    secrets.delete(id);
    
    res.json({
      encryptedData: secret.encryptedData,
      iv: secret.iv
    });
    
  } catch (error) {
    console.error('Retrieve error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/config', (req, res) => {
  res.json({
    maxSecretLength: MAX_SECRET_LENGTH,
    passwordConfig: {
      includeChars: PASSWORD_INCLUDE_CHARS,
      excludeChars: PASSWORD_EXCLUDE_CHARS,
      defaultSeparator: PASSPHRASE_SEPARATOR
    }
  });
});

app.post('/api/generate-password', (req, res) => {
  try {
    const { type, length, wordCount, separator } = req.body;
    
    if (type === 'password') {
      const passwordLength = Math.min(Math.max(parseInt(length) || 16, 4), 128);
      const password = generatePassword(passwordLength);
      res.json({ password });
    } else if (type === 'passphrase') {
      const words = Math.min(Math.max(parseInt(wordCount) || 4, 2), 10);
      const passphrase = generatePassphrase(words, separator);
      res.json({ password: passphrase });
    } else {
      res.status(400).json({ error: 'Invalid type. Must be "password" or "passphrase"' });
    }
  } catch (error) {
    console.error('Password generation error:', error);
    res.status(500).json({ error: 'Failed to generate password' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    activeSecrets: secrets.size,
    uptime: process.uptime()
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/view/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// HTTPS configuration for development
const useHTTPS = process.env.USE_HTTPS === 'true' || fs.existsSync('cert.pem');

if (useHTTPS && fs.existsSync('cert.pem') && fs.existsSync('key.pem')) {
  const httpsOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  };
  
  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`🔒 Secure password share server running on HTTPS port ${PORT}`);
    console.log(`🌐 Access at: https://localhost:${PORT}`);
    console.log(`📝 Note: You'll need to accept the self-signed certificate`);
    console.log(`💾 Memory-only storage - secrets will be lost on restart`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`Secure password share server running on HTTP port ${PORT}`);
    console.log(`Memory-only storage - secrets will be lost on restart`);
  });
}