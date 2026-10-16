const crypto = require('crypto');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const SESSION_SECRET = process.env.NDDU_SESSION_SECRET || '';
const COOKIE_SECURE = /^(1|true|yes)$/i.test(process.env.NDDU_COOKIE_SECURE || '');
const APPROVED_EXTERNAL_EMAILS = new Set(
  (process.env.APPROVED_EXTERNAL_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean)
);
const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
  let normalizedPath;
  try {
    normalizedPath = path.posix.normalize(decodeURIComponent(req.path));
  } catch {
    return res.status(400).end();
  }
  if (!['/', '/index.html', '/achievements.html'].includes(normalizedPath)) return next();
  if (!readSessionToken(req.cookies.auth)) return res.redirect('/login.html');
  return next();
});
app.use(express.static(__dirname));

function isAuthorizedEmail(email) {
  const normalized = email.trim().toLowerCase();
  const domain = normalized.slice(normalized.lastIndexOf('@') + 1);
  return domain === 'nddu.edu.ph' || APPROVED_EXTERNAL_EMAILS.has(normalized);
}

function createSessionToken(email) {
  const payload = Buffer.from(JSON.stringify({
    authenticated: true,
    email,
    expires_at: Math.floor(Date.now() / 1000) + 28800
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${signature}`;
}

function readSessionToken(token) {
  if (typeof token !== 'string') return null;

  const separator = token.indexOf('.');
  if (separator < 1) return null;

  const payloadPart = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  if (!/^[a-f0-9]{64}$/i.test(signature)) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payloadPart).digest();
  let provided;
  try {
    provided = Buffer.from(signature, 'hex');
  } catch {
    return null;
  }
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) return null;

  try {
    const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
    if (!payload.authenticated || payload.expires_at <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

app.get('/api/auth-config', (_req, res) => {
  res.json({ clientId: GOOGLE_CLIENT_ID });
});

app.post('/api/google-login', async (req, res) => {
  const credential = typeof req.body?.credential === 'string' ? req.body.credential.trim() : '';
  if (!credential) {
    return res.status(400).json({ success: false, message: 'Google credential is missing.' });
  }
  if (!GOOGLE_CLIENT_ID) {
    return res.status(503).json({ success: false, message: 'Google sign-in is not configured.' });
  }

  let googlePayload;
  try {
    const tokenInfoUrl = new URL('https://oauth2.googleapis.com/tokeninfo');
    tokenInfoUrl.searchParams.set('id_token', credential);
    const response = await fetch(tokenInfoUrl, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) {
      return res.status(401).json({ success: false, message: 'Google sign-in could not be verified.' });
    }
    googlePayload = await response.json();
  } catch (error) {
    console.error('Google token verification request failed.');
    return res.status(502).json({ success: false, message: 'Google sign-in could not be verified.' });
  }

  if (!googlePayload || typeof googlePayload !== 'object' || Array.isArray(googlePayload)) {
    return res.status(401).json({ success: false, message: 'Google sign-in could not be verified.' });
  }

  const email = typeof googlePayload.email === 'string' ? googlePayload.email.trim() : '';
  const emailVerified = googlePayload.email_verified === true || googlePayload.email_verified === 'true';
  const tokenNotExpired = Number(googlePayload.exp) * 1000 > Date.now();
  if (
    !EMAIL_PATTERN.test(email)
    || !emailVerified
    || googlePayload.aud !== GOOGLE_CLIENT_ID
    || !['accounts.google.com', 'https://accounts.google.com'].includes(googlePayload.iss)
    || !tokenNotExpired
  ) {
    return res.status(401).json({ success: false, message: 'Google account is not verified.' });
  }

  if (!isAuthorizedEmail(email)) {
    const message = email.toLowerCase().includes('nddu')
      ? 'An address containing “nddu” does not verify affiliation. Ask the repository administrator to approve your verified Google email.'
      : 'This Google email is not approved. Ask the repository administrator to approve it.';
    return res.status(403).json({ success: false, message });
  }

  res.cookie('auth', createSessionToken(email.toLowerCase()), {
    httpOnly: true,
    sameSite: 'lax',
    secure: COOKIE_SECURE,
    maxAge: 1000 * 60 * 60 * 8
  });
  return res.json({ success: true, message: 'Login successful.' });
});

app.post('/api/logout', (_req, res) => {
  res.clearCookie('auth', {
    httpOnly: true,
    sameSite: 'lax',
    secure: COOKIE_SECURE
  });
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  const user = readSessionToken(req.cookies.auth);
  if (!user) {
    return res.status(401).json({ success: false });
  }
  return res.json({ success: true, user });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

if (Buffer.byteLength(SESSION_SECRET, 'utf8') < 32) {
  console.error('NDDU_SESSION_SECRET must be set to at least 32 bytes.');
  process.exit(1);
}

const invalidApprovedEmails = [...APPROVED_EXTERNAL_EMAILS].filter((email) => !EMAIL_PATTERN.test(email));
if (invalidApprovedEmails.length > 0) {
  console.error('APPROVED_EXTERNAL_EMAILS contains an invalid email address.');
  process.exit(1);
}

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
