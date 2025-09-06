# 🔐 Secure Password Share

A secure, zero-knowledge password sharing application with client-side encryption, automatic expiration, and one-time access.

## 🛡️ Security Features

- **Client-side AES-256-GCM encryption** - Passwords are encrypted in the browser before transmission
- **Zero-knowledge architecture** - Server never sees plaintext data
- **One-time access** - Links self-destruct after first view
- **Automatic expiration** - Links expire after specified time (5 minutes to 7 days)
- **Secure random IDs** - Cryptographically secure link generation
- **Memory-only storage** - No persistent database, secrets cleared on restart
- **Rate limiting** - Protection against brute force attacks
- **Security headers** - Comprehensive HTTP security headers via Helmet.js
- **CSP protection** - Content Security Policy prevents XSS attacks

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start

# Development with auto-restart
npm run dev
```

The application will be available at `http://localhost:3000`

## 🔧 Configuration

Copy `.env.example` to `.env` and configure as needed:

```bash
cp .env.example .env
```

### Environment Variables

- `NODE_ENV` - Set to `production` for production deployment
- `PORT` - Server port (default: 3000)
- `ALLOWED_ORIGINS` - Comma-separated list of allowed origins for CORS

## 🏗️ Architecture

### Security Architecture
```
Browser (Client-side)           Server (Zero-knowledge)
┌─────────────────────┐        ┌─────────────────────┐
│ 1. Generate AES key │        │                     │
│ 2. Encrypt password │        │  Store encrypted    │
│ 3. Key in URL hash  │───────▶│  data + metadata    │
│ 4. Send ciphertext  │        │  (never plaintext)  │
└─────────────────────┘        └─────────────────────┘
```

### Data Flow
1. **Create Secret**: User enters password → Client generates AES-256 key → Client encrypts data → Send ciphertext to server → Server stores encrypted data → Return secure link with key in URL hash
2. **Access Secret**: User clicks link → Extract key from URL hash → Request encrypted data → Client decrypts → Display plaintext → Delete from server

### Security Boundaries
- **Client-side**: Encryption/decryption, key generation, plaintext handling
- **Server-side**: Encrypted data storage, expiration, access control, rate limiting
- **Transport**: HTTPS encryption, security headers, CORS protection

## 🔒 Security Implementation Details

### Encryption
- **Algorithm**: AES-256-GCM (Authenticated encryption)
- **Key derivation**: Secure random generation (crypto.getRandomValues)
- **IV/Nonce**: 12-byte random nonce per encryption
- **Encoding**: Base64URL for safe URL transmission

### Access Control
- **One-time access**: Secret deleted immediately after retrieval
- **Time-based expiration**: Configurable expiration (5 min - 7 days)
- **Secure IDs**: 32-byte random IDs (base64url encoded)

### Rate Limiting
- **Creation**: 10 secrets per 15 minutes per IP
- **Retrieval**: 50 attempts per 15 minutes per IP

### Security Headers
```javascript
Content-Security-Policy: default-src 'self'; script-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
```

## 🧪 Testing the Security

### Manual Security Tests

1. **Encryption Verification**:
   ```javascript
   // Check that different encryptions of same text produce different ciphertexts
   console.log(await encryptText("test123"));
   console.log(await encryptText("test123"));
   // Should produce different encryptedData and iv values
   ```

2. **One-time Access**:
   - Create a secret, access it once → should work
   - Try accessing the same link again → should fail with 404

3. **Expiration Test**:
   - Create a secret with 5-minute expiration
   - Wait 5+ minutes, try accessing → should fail

4. **Server Knowledge Test**:
   - Check server logs/memory → should never contain plaintext
   - Server stores only: `{encryptedData, iv, expiresAt, accessed}`

### Rate Limiting Test
```bash
# Test creation rate limit (should block after 10 requests)
for i in {1..15}; do curl -X POST http://localhost:3000/api/store -H "Content-Type: application/json" -d '{"encryptedData":"test","iv":"test","expirationMinutes":5}'; done
```

## 🚨 Security Considerations

### Deployment Security
- **Always use HTTPS** in production
- **Set secure environment variables**
- **Configure proper CORS origins**
- **Use a reverse proxy** (nginx/Apache) for additional security
- **Monitor server logs** for suspicious activity

### Client Security
- **Clear browser history** after viewing secrets
- **Use private browsing** for sensitive secrets
- **Don't share links over insecure channels** (unencrypted email, SMS)
- **Verify HTTPS connection** before entering sensitive data

### Operational Security
- **Restart server regularly** to clear all secrets from memory
- **Monitor memory usage** to detect potential issues
- **Use process isolation** in production environments
- **Implement proper logging** (without sensitive data)

## 🔄 Memory Management

The application uses in-memory storage for maximum security:
- **No persistent database** - all secrets lost on restart
- **Automatic cleanup** - expired secrets cleaned every minute
- **Immediate deletion** - secrets deleted after access
- **Memory protection** - sensitive data cleared from variables

## 📊 API Endpoints

### POST /api/store
Create a new encrypted secret.

**Request:**
```json
{
  "encryptedData": "base64url-encoded-ciphertext",
  "iv": "base64url-encoded-iv",
  "expirationMinutes": 60
}
```

**Response:**
```json
{
  "id": "secure-random-id",
  "expiresAt": "2024-01-01T12:00:00.000Z"
}
```

### GET /api/retrieve/:id
Retrieve and delete an encrypted secret.

**Response:**
```json
{
  "encryptedData": "base64url-encoded-ciphertext",
  "iv": "base64url-encoded-iv"
}
```

### GET /api/health
Health check endpoint.

## 🛡️ Security Audit Checklist

- [ ] Client-side encryption implemented correctly
- [ ] Server never accesses plaintext data
- [ ] One-time access enforced
- [ ] Automatic expiration working
- [ ] Rate limiting configured
- [ ] Security headers present
- [ ] HTTPS enforced in production
- [ ] Memory cleared after use
- [ ] No sensitive data in logs
- [ ] CSP preventing XSS
- [ ] Secure random ID generation
- [ ] Input validation on all endpoints

## 📄 License

MIT License - Use responsibly for legitimate security purposes only.

## ⚠️ Disclaimer

This application is designed for legitimate password sharing needs. Users are responsible for compliance with applicable laws and regulations. The zero-knowledge architecture means that lost encryption keys cannot be recovered.