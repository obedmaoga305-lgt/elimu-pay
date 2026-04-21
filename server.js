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
const helmet       = require('helmet');
const morgan       = require('morgan');
const rateLimit    = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// ─────────────────────────────────────────
//  App & Middleware
// ─────────────────────────────────────────
const app = express();

app.use(express.json());
app.use(cors({ origin: '*' }));
app.use(morgan('dev'));
app.use(
  helmet({
    contentSecurityPolicy: false, // allow inline scripts in public HTML
    crossOriginEmbedderPolicy: false,
  })
);

// ─────────────────────────────────────────
//  Rate Limiters
// ─────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Too many requests. Please wait 15 minutes and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  message: { error: 'Too many requests. Please slow down.' },
});

app.use('/api/login',    authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/',         generalLimiter);

// ─────────────────────────────────────────
//  Supabase Client
// ─────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────

function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip']                              ||
    req.socket?.remoteAddress                             ||
    'unknown'
  );
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitize(str) {
  return typeof str === 'string' ? str.trim() : str;
}

// ─────────────────────────────────────────
//  Middleware — Auth Guards
// ─────────────────────────────────────────

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized — no token provided' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden — admin only' });
    }
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─────────────────────────────────────────
//  Access Check
// ─────────────────────────────────────────

async function checkUserAccess(userId) {
  const { data } = await supabase
    .from('sessions')
    .select('expires_at')
    .eq('user_id', userId)
    .gt('expires_at', new Date().toISOString())
    .order('expires_at', { ascending: false })
    .limit(1)
    .single();

  return data
    ? { hasAccess: true,  expiresAt: data.expires_at }
    : { hasAccess: false, expiresAt: null };
}

// ─────────────────────────────────────────
//  M-Pesa Helpers
// ─────────────────────────────────────────

async function getMpesaToken() {
  const key    = process.env.MPESA_CONSUMER_KEY?.trim();
  const secret = process.env.MPESA_CONSUMER_SECRET?.trim();
  const auth   = Buffer.from(`${key}:${secret}`).toString('base64');
  const env    = process.env.MPESA_ENV === 'live' ? 'api' : 'sandbox';

  const { data } = await axios.get(
    `https://${env}.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials`,
    { headers: { Authorization: `Basic ${auth}` } }
  );
  return data.access_token;
}

async function stkPush({ phone, amount }) {
  const token     = await getMpesaToken();
  const timestamp = new Date().toISOString().replace(/[-T:.Z]/g, '').slice(0, 14);
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey   = process.env.MPESA_PASSKEY;
  const password  = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
  const env       = process.env.MPESA_ENV === 'live' ? 'api' : 'sandbox';

  const { data } = await axios.post(
    `https://${env}.safaricom.co.ke/mpesa/stkpush/v1/processrequest`,
    {
      BusinessShortCode: shortcode,
      Password:          password,
      Timestamp:         timestamp,
      TransactionType:   'CustomerPayBillOnline',
      Amount:            amount,
      PartyA:            phone,
      PartyB:            shortcode,
      PhoneNumber:       phone,
      CallBackURL:       `${process.env.BACKEND_URL}/api/pay/callback`,
      AccountReference:  'ElimuPay',
      TransactionDesc:   '30min Video Access',
    },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return data;
}

// ═══════════════════════════════════════════════════════
//  ROUTES — AUTH
// ═══════════════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const name     = sanitize(req.body.name);
    const email    = sanitize(req.body.email)?.toLowerCase();
    const password = sanitize(req.body.password);

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const { data: existing, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      console.error('Register DB check error:', checkError);
      return res.status(500).json({ error: 'Database error. Please try again.' });
    }
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const { error: insertError } = await supabase.from('users').insert({
      name,
      email,
      password: hashedPassword,
    });

    if (insertError) {
      console.error('Register insert error:', insertError);
      return res.status(500).json({ error: 'Registration failed. Please try again.' });
    }

    res.status(201).json({ message: 'Account created successfully! Please log in.' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const email    = sanitize(req.body.email)?.toLowerCase();
    const password = sanitize(req.body.password);
    const ip       = getIP(req);
    const userAgent = req.headers['user-agent'] || '';

    if (!email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    const success = user && (await bcrypt.compare(password, user.password));

    await supabase.from('login_attempts').insert({
      email,
      ip,
      user_agent: userAgent,
      status: success ? 'success' : 'failed',
    });

    if (!success) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token  = signToken({ userId: user.id, email: user.email });
    const access = await checkUserAccess(user.id);

    res.json({
      token,
      hasAccess: access.hasAccess,
      expiresAt: access.expiresAt,
      name:      user.name,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// GET /api/check-access
app.get('/api/check-access', verifyToken, async (req, res) => {
  try {
    const access = await checkUserAccess(req.user.userId);
    res.json(access);
  } catch (err) {
    console.error('Check access error:', err);
    res.status(500).json({ error: 'Access check failed' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — PAYMENTS
// ═══════════════════════════════════════════════════════

// POST /api/pay/initiate
app.post('/api/pay/initiate', verifyToken, async (req, res) => {
  try {
    const phone = sanitize(req.body.phone);
    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    // Validate Kenyan phone format
    const phoneClean = phone.replace(/\s+/g, '');
    if (!/^2547\d{8}$/.test(phoneClean)) {
      return res.status(400).json({ error: 'Enter a valid Safaricom number e.g. 2547XXXXXXXX' });
    }

    const result = await stkPush({ phone: phoneClean, amount: 10 });

    if (result.ResponseCode !== '0') {
      return res.status(400).json({
        error: result.ResponseDescription || 'M-Pesa request failed',
      });
    }

    await supabase.from('payments').insert({
      user_id:             req.user.userId,
      email:               req.user.email,
      phone:               phoneClean,
      amount:              10,
      checkout_request_id: result.CheckoutRequestID,
      status:              'pending',
    });

    res.json({
      message:           'STK push sent — check your phone',
      checkoutRequestId: result.CheckoutRequestID,
    });
  } catch (err) {
    console.error('STK push error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Payment initiation failed. Please try again.' });
  }
});

// POST /api/pay/callback  (M-Pesa webhook — always return 200)
app.post('/api/pay/callback', async (req, res) => {
  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) return res.sendStatus(200);

    const { CheckoutRequestID: checkoutRequestId, ResultCode: resultCode } = body;

    if (resultCode === 0) {
      const items    = body.CallbackMetadata?.Item || [];
      const getItem  = name => items.find(i => i.Name === name)?.Value;
      const mpesaRef = getItem('MpesaReceiptNumber');
      const amount   = getItem('Amount');

      await supabase
        .from('payments')
        .update({ status: 'paid', mpesa_ref: mpesaRef, amount })
        .eq('checkout_request_id', checkoutRequestId);

      const { data: payment } = await supabase
        .from('payments')
        .select('user_id')
        .eq('checkout_request_id', checkoutRequestId)
        .single();

      if (payment) {
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        await supabase.from('sessions').insert({
          user_id:    payment.user_id,
          expires_at: expiresAt,
        });
        console.log(`✅ Access granted to user ${payment.user_id} until ${expiresAt}`);
      }
    } else {
      await supabase
        .from('payments')
        .update({ status: 'failed' })
        .eq('checkout_request_id', checkoutRequestId);
      console.log(`❌ Payment failed/cancelled — CheckoutRequestID: ${checkoutRequestId}`);
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Callback error:', err);
    res.sendStatus(200); // Always 200 to M-Pesa
  }
});

// GET /api/pay/status/:checkoutRequestId
app.get('/api/pay/status/:checkoutRequestId', verifyToken, async (req, res) => {
  try {
    const { checkoutRequestId } = req.params;

    const { data } = await supabase
      .from('payments')
      .select('status, mpesa_ref, amount, created_at')
      .eq('checkout_request_id', checkoutRequestId)
      .single();

    if (!data) {
      return res.status(404).json({ error: 'Payment record not found' });
    }

    res.json(data);
  } catch (err) {
    console.error('Status error:', err);
    res.status(500).json({ error: 'Status check failed' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — VIDEOS
// ═══════════════════════════════════════════════════════

// GET /api/videos  (requires paid access)
app.get('/api/videos', verifyToken, async (req, res) => {
  try {
    const access = await checkUserAccess(req.user.userId);
    if (!access.hasAccess) {
      return res.status(403).json({ error: 'Payment required to access videos', code: 'NO_ACCESS' });
    }

    const { subject, grade } = req.query;
    let query = supabase
      .from('videos')
      .select('id, title, description, url, thumbnail, subject, grade, duration, views')
      .eq('is_active', true)
      .order('created_at', { ascending: false });

    if (subject) query = query.eq('subject', subject);
    if (grade)   query = query.eq('grade', grade);

    const { data, error } = await query;
    if (error) throw error;

    res.json({ videos: data, expiresAt: access.expiresAt });
  } catch (err) {
    console.error('Videos fetch error:', err);
    res.status(500).json({ error: 'Failed to load videos' });
  }
});

// POST /api/videos/:id/view  (increment view counter)
app.post('/api/videos/:id/view', verifyToken, async (req, res) => {
  try {
    const access = await checkUserAccess(req.user.userId);
    if (!access.hasAccess) {
      return res.status(403).json({ error: 'Payment required', code: 'NO_ACCESS' });
    }

    await supabase.rpc('increment_views', { video_id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to record view' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — ADMIN
// ═══════════════════════════════════════════════════════

// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }
    const token = signToken({ role: 'admin' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Admin login failed' });
  }
});

// GET /api/admin/stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admin_stats').select('*').single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// GET /api/admin/users
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, name, email, created_at')
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) throw error;
    res.json({ users: data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

// GET /api/admin/payments
app.get('/api/admin/payments', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('payments')
      .select('id, email, phone, amount, status, mpesa_ref, created_at')
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) throw error;
    res.json({ payments: data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load payments' });
  }
});

// GET /api/admin/attempts
app.get('/api/admin/attempts', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('login_attempts')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json({ attempts: data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load login attempts' });
  }
});

// POST /api/admin/videos  (add a video)
app.post('/api/admin/videos', verifyAdmin, async (req, res) => {
  try {
    const { title, description, url, thumbnail, subject, grade, duration } = req.body;
    if (!title || !url) {
      return res.status(400).json({ error: 'Title and URL are required' });
    }
    const { data, error } = await supabase
      .from('videos')
      .insert({ title, description, url, thumbnail, subject, grade, duration })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ message: 'Video added successfully', video: data });
  } catch (err) {
    console.error('Add video error:', err);
    res.status(500).json({ error: 'Failed to add video' });
  }
});

// DELETE /api/admin/videos/:id
app.delete('/api/admin/videos/:id', verifyAdmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('videos')
      .update({ is_active: false })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Video removed successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to remove video' });
  }
});

// ─────────────────────────────────────────
//  Health Check
// ─────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), service: 'ElimuPay API' });
});

// ─────────────────────────────────────────
//  Static Files & SPA Fallback
// ─────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────
//  Start Server
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  ╔════════════════════════════════════════╗`);
  console.log(`  ║   ElimuPay server is running 🚀        ║`);
  console.log(`  ║   http://localhost:${PORT}                ║`);
  console.log(`  ║   ENV: ${process.env.MPESA_ENV || 'sandbox'}                     ║`);
  console.log(`  ╚════════════════════════════════════════╝\n`);
});
