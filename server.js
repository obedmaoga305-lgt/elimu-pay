// ╔══════════════════════════════════════════════════════╗
// ║              ElimuPay — Backend Server               ║
// ║         Educational Video Platform · Kenya           ║
// ╚══════════════════════════════════════════════════════╝

require('dotenv').config();

const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const axios        = require('axios');
const path         = require('path');
const crypto       = require('crypto');
const helmet       = require('helmet');
const morgan       = require('morgan');
const rateLimit    = require('express-rate-limit');
const nodemailer   = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

// ─────────────────────────────────────────
//  App & Middleware
// ─────────────────────────────────────────
const app = express();

app.set('trust proxy', 1);

app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

app.use(express.json());
app.use(cors({ origin: '*' }));
app.use(morgan('dev'));
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// ─────────────────────────────────────────
//  Rate Limiters
// ─────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const forgotLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5 });
const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/forgot-password', forgotLimiter);
app.use('/api/', generalLimiter);

// ─────────────────────────────────────────
//  Supabase Client
// ─────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─────────────────────────────────────────
//  Email (Nodemailer)
// ─────────────────────────────────────────
const mailer = nodemailer.createTransport({
  host:   process.env.EMAIL_HOST || 'smtp.gmail.com',
  port:   parseInt(process.env.EMAIL_PORT || '587'),
  secure: false,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

async function sendEmail({ to, subject, html }) {
  if (!process.env.EMAIL_USER) return;
  await mailer.sendMail({ from: `"ElimuPay" <${process.env.EMAIL_USER}>`, to, subject, html });
}

function emailTemplate({ title, body, btnText, btnUrl }) {
  return `
  <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#f9fafb;padding:24px;border-radius:12px;">
    <div style="background:#16a34a;padding:20px;border-radius:8px 8px 0 0;text-align:center;">
      <h1 style="color:#fff;margin:0;font-size:1.4rem;">📚 ElimuPay</h1>
    </div>
    <div style="background:#fff;padding:28px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
      <h2 style="color:#052e16;margin-bottom:12px;">${title}</h2>
      ${body}
      ${btnText && btnUrl ? `<a href="${btnUrl}" style="display:inline-block;margin-top:20px;padding:12px 28px;background:#16a34a;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;">${btnText}</a>` : ''}
    </div>
  </div>`;
}

// ─────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}
function signToken(payload) { return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' }); }
function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function sanitize(str) { return typeof str === 'string' ? str.trim() : str; }

// ─────────────────────────────────────────
//  Middleware — Auth Guards
// ─────────────────────────────────────────
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function checkUserAccess(userId) {
  const { data } = await supabase.from('sessions').select('expires_at').eq('user_id', userId).gt('expires_at', new Date().toISOString()).order('expires_at', { ascending: false }).limit(1).single();
  return data ? { hasAccess: true, expiresAt: data.expires_at } : { hasAccess: false, expiresAt: null };
}

async function getMpesaToken() {
  const key = process.env.MPESA_CONSUMER_KEY?.trim();
  const secret = process.env.MPESA_CONSUMER_SECRET?.trim();
  const auth = Buffer.from(`${key}:${secret}`).toString('base64');
  const env = process.env.MPESA_ENV === 'live' ? 'api' : 'sandbox';
  const { data } = await axios.get(`https://${env}.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials`, { headers: { Authorization: `Basic ${auth}` } });
  return data.access_token;
}

async function stkPush({ phone, amount }) {
  const token = await getMpesaToken();
  const timestamp = new Date().toISOString().replace(/[-T:.Z]/g, '').slice(0, 14);
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;
  const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
  const env = process.env.MPESA_ENV === 'live' ? 'api' : 'sandbox';
  const { data } = await axios.post(
    `https://${env}.safaricom.co.ke/mpesa/stkpush/v1/processrequest`,
    { BusinessShortCode: shortcode, Password: password, Timestamp: timestamp, TransactionType: 'CustomerPayBillOnline', Amount: amount, PartyA: phone, PartyB: shortcode, PhoneNumber: phone, CallBackURL: `${process.env.BACKEND_URL}/api/pay/callback`, AccountReference: 'ElimuPay', TransactionDesc: '30min Video Access' },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return data;
}

// ═══════════════════════════════════════════════════════
//  ROUTES — AUTH
// ═══════════════════════════════════════════════════════
app.post('/api/register', async (req, res) => {
  try {
    const name = sanitize(req.body.name);
    const email = sanitize(req.body.email)?.toLowerCase();
    const password = sanitize(req.body.password);
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

    const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
    if (existing) return res.status(409).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 12);
    await supabase.from('users').insert({ name, email, password: hashedPassword });
    res.status(201).json({ message: 'Account created successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = sanitize(req.body.email)?.toLowerCase();
    const password = sanitize(req.body.password);
    if (!email || !password) return res.status(400).json({ error: 'All fields are required' });

    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    const success = user && !user.is_banned && (await bcrypt.compare(password, user.password));

    if (!success) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ userId: user.id, email: user.email });
    const access = await checkUserAccess(user.id);

    res.json({ token, hasAccess: access.hasAccess, expiresAt: access.expiresAt, name: user.name });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/check-access', verifyToken, async (req, res) => {
  try {
    const access = await checkUserAccess(req.user.userId);
    res.json(access);
  } catch (err) {
    res.status(500).json({ error: 'Access check failed' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const email = sanitize(req.body.email)?.toLowerCase();
    const { data: user } = await supabase.from('users').select('id, name').eq('email', email).single();
    res.json({ message: 'If registered, a reset link was sent.' });
    if (!user) return;
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await supabase.from('password_resets').insert({ user_id: user.id, email, token, expires_at: expiresAt });
    const resetUrl = `${process.env.BACKEND_URL}/reset-password.html?token=${token}`;
    sendEmail({ to: email, subject: '🔑 Password Reset', html: emailTemplate({ title: 'Password Reset', body: `<p>Click the link to reset.</p>`, btnText: 'Reset Password', btnUrl: resetUrl }) }).catch(console.error);
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    const { data: reset } = await supabase.from('password_resets').select('*').eq('token', token).gt('expires_at', new Date().toISOString()).eq('used', false).single();
    if (!reset) return res.status(400).json({ error: 'Invalid token' });
    const hashed = await bcrypt.hash(password, 12);
    await supabase.from('users').update({ password: hashed }).eq('id', reset.user_id);
    await supabase.from('password_resets').update({ used: true }).eq('token', token);
    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Reset failed' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — PAYMENTS
// ═══════════════════════════════════════════════════════
app.post('/api/pay/initiate', verifyToken, async (req, res) => {
  try {
    const phone = sanitize(req.body.phone)?.replace(/\s+/g, '');
    const result = await stkPush({ phone, amount: 10 });
    if (result.ResponseCode !== '0') return res.status(400).json({ error: 'M-Pesa request failed' });
    await supabase.from('payments').insert({ user_id: req.user.userId, email: req.user.email, phone, amount: 10, checkout_request_id: result.CheckoutRequestID, status: 'pending' });
    res.json({ message: 'STK push sent', checkoutRequestId: result.CheckoutRequestID });
  } catch (err) {
    res.status(500).json({ error: 'Payment failed' });
  }
});

app.post('/api/pay/callback', async (req, res) => {
  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) return res.sendStatus(200);
    const { CheckoutRequestID: checkoutRequestId, ResultCode: resultCode } = body;
    if (resultCode === 0) {
      const items = body.CallbackMetadata?.Item || [];
      const getItem = name => items.find(i => i.Name === name)?.Value;
      const mpesaRef = getItem('MpesaReceiptNumber');
      const amount = getItem('Amount');
      await supabase.from('payments').update({ status: 'paid', mpesa_ref: mpesaRef, amount }).eq('checkout_request_id', checkoutRequestId);
      const { data: payment } = await supabase.from('payments').select('user_id, email, phone').eq('checkout_request_id', checkoutRequestId).single();
      if (payment) {
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        await supabase.from('sessions').insert({ user_id: payment.user_id, expires_at: expiresAt });
      }
    } else {
      await supabase.from('payments').update({ status: 'failed' }).eq('checkout_request_id', checkoutRequestId);
    }
    res.sendStatus(200);
  } catch (err) {
    res.sendStatus(200);
  }
});

app.get('/api/pay/status/:checkoutRequestId', verifyToken, async (req, res) => {
  try {
    const { data } = await supabase.from('payments').select('status, mpesa_ref, amount, created_at').eq('checkout_request_id', req.params.checkoutRequestId).single();
    if (!data) return res.status(404).json({ error: 'Not found' });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Status check failed' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — VIDEOS (100% FREE AND BULLETPROOF)
// ═══════════════════════════════════════════════════════
app.get('/api/videos', async (req, res) => {
  try {
    // Selects ALL records to prevent crashing if database columns are missing.
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase fetch error:', error);
      return res.status(500).json({ error: error.message });
    }

    res.json({ videos: data || [] });
  } catch (err) {
    console.error('Video fetch crash:', err);
    res.status(500).json({ error: 'Failed to load videos from backend' });
  }
});

app.post('/api/videos/:id/view', async (req, res) => {
  try {
    const { data: video } = await supabase.from('videos').select('views').eq('id', req.params.id).single();
    if (video) {
      await supabase.from('videos').update({ views: (video.views || 0) + 1 }).eq('id', req.params.id);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — ADMIN
// ═══════════════════════════════════════════════════════
app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid admin password' });
    const token = signToken({ role: 'admin' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Admin login failed' });
  }
});

app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('admin_stats').select('*').single();
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('id, name, email, is_banned, created_at').order('created_at', { ascending: false }).limit(200);
    res.json({ users: data });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/users/:id/ban', verifyAdmin, async (req, res) => {
  try {
    const { ban } = req.body;
    await supabase.from('users').update({ is_banned: !!ban }).eq('id', req.params.id);
    if (ban) await supabase.from('sessions').delete().eq('user_id', req.params.id);
    res.json({ message: 'Success' });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/payments', verifyAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('payments').select('id, email, phone, amount, status, mpesa_ref, created_at').order('created_at', { ascending: false }).limit(200);
    res.json({ payments: data });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/attempts', verifyAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('login_attempts').select('*').order('created_at', { ascending: false }).limit(200);
    res.json({ attempts: data });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/all-videos', verifyAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('videos').select('*').order('created_at', { ascending: false });
    res.json({ videos: data });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/videos', verifyAdmin, async (req, res) => {
  try {
    const { title, description, url, thumbnail, subject, grade, duration } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'Title and URL are required' });

    const { data, error } = await supabase.from('videos').insert({ title, description, url, thumbnail, subject, grade, duration }).select().single();
    
    if (error) {
      console.error('Database Insert Error:', error);
      return res.status(400).json({ error: error.message });
    }

    res.status(201).json({ message: 'Video added successfully', video: data });
  } catch (err) {
    console.error('Admin upload error:', err);
    res.status(500).json({ error: 'Failed to add video' });
  }
});

app.delete('/api/admin/videos/:id', verifyAdmin, async (req, res) => {
  try {
    await supabase.from('videos').update({ is_active: false }).eq('id', req.params.id);
    res.json({ message: 'Removed' });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// ─────────────────────────────────────────
//  Static Files & SPA Fallback
// ─────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

// ─────────────────────────────────────────
//  Start Server
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  ╔═══════════════════════════════════════════╗`);
  console.log(`  ║   ElimuPay server is running 🚀           ║`);
  console.log(`  ║   http://localhost:${PORT}                   ║`);
  console.log(`  ╚═══════════════════════════════════════════╝\n`);
});
