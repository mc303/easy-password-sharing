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
app.use(express.static('public'));

const createLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: { error: 'Too many secrets created, try again later' }
});

const retrieveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes  
  max: 50, // limit each IP to 50 requests per windowMs
  message: { error: 'Too many retrieval attempts, try again later' }
});

const secrets = new Map();

function generateSecureId() {
  return crypto.randomBytes(32).toString('base64url');
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