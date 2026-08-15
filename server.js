const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

require('dotenv').config();

const app = express();
app.set('trust proxy', 1); // Trust Render's reverse proxy
app.use(express.json());
app.use(helmet());

// ── Config ────────────────────────────────────────────────────────────────────
const MARZPAY_BASE = process.env.MARZPAY_BASE_URL || 'https://wallet.wearemarz.com/api/v1';
const MARZPAY_AUTH = process.env.MARZPAY_AUTH || '';
const EGOSMS_USERNAME = process.env.EGOSMS_USERNAME || 'INFINITECH';
const EGOSMS_PASSWORD = process.env.EGOSMS_PASSWORD || '';
const EGOSMS_SENDER = process.env.EGOSMS_SENDER || 'Mbeera';

const PROXY_KEYS = new Set([
  process.env.PROXY_KEY || 'mbeera_lending_2025_proxy_key',
]);

// In-memory OTP store (production: use Redis/Firestore)
const otpStore = new Map(); // phone -> { code, expiresAt, attempts }

// ── Rate Limiting ─────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: { status: 'error', message: 'Too many requests. Try again later.' },
});
app.use(limiter);

// Strict rate limit for auth endpoints (5 attempts per 15 min)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { status: 'error', message: 'Too many attempts. Account locked for 15 minutes.' },
});

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Proxy-Key, Cache-Control');
  res.header('Cache-Control', 'no-store, no-cache');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── Auth Middleware ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/') return next();
  const key = req.headers['x-proxy-key'];
  if (!PROXY_KEYS.has(key)) {
    return res.status(403).json({ status: 'error', message: 'Unauthorized' });
  }
  next();
});

// ── Shared MarzPay headers ────────────────────────────────────────────────────
const marzHeaders = {
  'Authorization': `Basic ${MARZPAY_AUTH}`,
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Cache-Control': 'no-cache',
};

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', async (_, res) => {
  try {
    const r = await axios.get('https://api.ipify.org?format=json');
    res.json({ status: 'ok', service: 'Mbeera Proxy v1.0.0', ip: r.data.ip });
  } catch {
    res.json({ status: 'ok', service: 'Mbeera Proxy v1.0.0' });
  }
});

app.get('/', (_, res) => {
  res.json({ status: 'ok', service: 'Mbeera Proxy v1.0.0' });
});

// ════════════════════════════════════════════════════════════════════════════════
// EGO SMS — OTP Generation & Verification
// ════════════════════════════════════════════════════════════════════════════════

// Generate and send OTP
app.post('/auth/send-otp', authLimiter, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone || !phone.startsWith('+256') || phone.length < 13) {
      return res.status(400).json({ success: false, message: 'Invalid Uganda phone number' });
    }

    // Generate 6-digit OTP
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    // Store OTP
    otpStore.set(phone, { code, expiresAt, attempts: 0 });

    // Send via EgoSMS
    const normalizedPhone = phone.replace('+', '');
    const message = `Your Mbeera verification code is: ${code}. Valid for 5 minutes. Do NOT share this code with anyone.`;

    const smsUrl = `https://www.egosms.co/api/v1/plain/?number=${normalizedPhone}&message=${encodeURIComponent(message)}&username=${EGOSMS_USERNAME}&password=${encodeURIComponent(EGOSMS_PASSWORD)}&sender=${EGOSMS_SENDER}`;

    const smsResp = await axios.get(smsUrl, { timeout: 15000 });
    console.log(`[OTP-SEND] ${phone} → code sent (EgoSMS: ${smsResp.status})`);

    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (e) {
    console.error('[OTP-SEND]', e.message);
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/auth/verify-otp', authLimiter, async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (!phone || !code) {
      return res.status(400).json({ success: false, message: 'Phone and code required' });
    }

    const stored = otpStore.get(phone);
    if (!stored) {
      return res.status(400).json({ success: false, message: 'No OTP found. Please request a new one.' });
    }

    // Check expiry
    if (Date.now() > stored.expiresAt) {
      otpStore.delete(phone);
      return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
    }

    // Check attempts (max 3)
    if (stored.attempts >= 3) {
      otpStore.delete(phone);
      return res.status(429).json({ success: false, message: 'Too many failed attempts. Request a new code.' });
    }

    // Verify
    if (stored.code !== code) {
      stored.attempts++;
      return res.status(400).json({
        success: false,
        message: `Incorrect code. ${3 - stored.attempts} attempts remaining.`,
      });
    }

    // Success — clean up
    otpStore.delete(phone);
    console.log(`[OTP-VERIFY] ${phone} → verified ✓`);

    res.json({ success: true, message: 'Phone verified successfully' });
  } catch (e) {
    console.error('[OTP-VERIFY]', e.message);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// EGO SMS — Send arbitrary SMS (notifications, reminders, etc.)
// ════════════════════════════════════════════════════════════════════════════════
app.post('/sms/send', async (req, res) => {
  try {
    const { phone, message } = req.body;
    if (!phone || !message) {
      return res.status(400).json({ success: false, message: 'Phone and message required' });
    }

    const normalizedPhone = phone.replace('+', '').replace(/\s/g, '');
    const smsUrl = `https://www.egosms.co/api/v1/plain/?number=${normalizedPhone}&message=${encodeURIComponent(message)}&username=${EGOSMS_USERNAME}&password=${encodeURIComponent(EGOSMS_PASSWORD)}&sender=${EGOSMS_SENDER}`;

    await axios.get(smsUrl, { timeout: 15000 });
    console.log(`[SMS-SEND] → ${normalizedPhone}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[SMS-SEND]', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// MARZPAY — Phone Verification (name lookup by phone number)
// ════════════════════════════════════════════════════════════════════════════════
app.post('/verify/phone', async (req, res) => {
  try {
    console.log('[PHONE-VERIFY] Request:', JSON.stringify(req.body));
    const r = await axios.post(
      `${MARZPAY_BASE}/phone-verification/verify`,
      req.body,
      { headers: marzHeaders }
    );
    console.log('[PHONE-VERIFY] Response:', JSON.stringify(r.data));
    res.json(r.data);
  } catch (e) {
    console.error('[PHONE-VERIFY]', e.message, e.response?.data);
    res.json(e.response?.data ?? { success: false, message: e.message });
  }
});

app.get('/verify/phone/service-info', async (_, res) => {
  try {
    const r = await axios.get(
      `${MARZPAY_BASE}/phone-verification/service-info`,
      { headers: marzHeaders }
    );
    res.json(r.data);
  } catch (e) {
    res.json(e.response?.data ?? { success: false, message: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// MARZPAY — Mobile Money Collect (repayments from borrowers)
// ════════════════════════════════════════════════════════════════════════════════
app.post('/payments/collect', async (req, res) => {
  try {
    console.log('[COLLECT] Request:', JSON.stringify(req.body));
    const r = await axios.post(
      `${MARZPAY_BASE}/collect-money`,
      req.body,
      { headers: marzHeaders }
    );
    console.log('[COLLECT] Response:', JSON.stringify(r.data));
    res.json(r.data);
  } catch (e) {
    console.error('[COLLECT]', e.message, e.response?.data);
    res.json(e.response?.data ?? { status: 'error', message: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// MARZPAY — Mobile Money Disburse (send loan funds to borrower)
// ════════════════════════════════════════════════════════════════════════════════
app.post('/payments/disburse', async (req, res) => {
  try {
    console.log('[DISBURSE] Request:', JSON.stringify(req.body));
    const r = await axios.post(
      `${MARZPAY_BASE}/send-money`,
      req.body,
      { headers: marzHeaders }
    );
    console.log('[DISBURSE] Response:', JSON.stringify(r.data));
    res.json(r.data);
  } catch (e) {
    console.error('[DISBURSE]', e.message, e.response?.data);
    res.json(e.response?.data ?? { status: 'error', message: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// MARZPAY — Transaction Status Check
// ════════════════════════════════════════════════════════════════════════════════
app.get('/payments/status/:uuid', async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  try {
    const url = `${MARZPAY_BASE}/collect-money/${req.params.uuid}?_t=${Date.now()}`;
    const r = await axios.get(url, {
      headers: { ...marzHeaders, 'Cache-Control': 'no-cache, no-store' },
    });
    res.json(r.data);
  } catch (e) {
    console.error('[STATUS]', e.message, e.response?.data);
    res.json(e.response?.data ?? { status: 'error', message: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// MARZPAY — Bank Transfer (future: for larger disbursements)
// ════════════════════════════════════════════════════════════════════════════════
app.get('/bank/banks', async (_, res) => {
  try {
    const r = await axios.get(`${MARZPAY_BASE}/bank-transfer/banks`, { headers: marzHeaders });
    res.json(r.data);
  } catch (e) {
    res.json(e.response?.data ?? { status: 'error', message: e.message });
  }
});

app.post('/bank/transfer', async (req, res) => {
  try {
    console.log('[BANK-TRANSFER] Request:', JSON.stringify(req.body));
    const r = await axios.post(`${MARZPAY_BASE}/bank-transfer`, req.body, { headers: marzHeaders });
    console.log('[BANK-TRANSFER] Response:', JSON.stringify(r.data));
    res.json(r.data);
  } catch (e) {
    console.error('[BANK-TRANSFER]', e.message, e.response?.data);
    res.json(e.response?.data ?? { status: 'error', message: e.message });
  }
});

app.get('/bank/status/:reference', async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  try {
    const url = `${MARZPAY_BASE}/bank-transfer/${req.params.reference}?_t=${Date.now()}`;
    const r = await axios.get(url, { headers: { ...marzHeaders, 'Cache-Control': 'no-cache, no-store' } });
    res.json(r.data);
  } catch (e) {
    res.json(e.response?.data ?? { status: 'error', message: e.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✓ Mbeera Proxy v1.0.0 running on port ${PORT}`));
