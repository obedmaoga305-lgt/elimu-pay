require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
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
    return res.status(401).json({ error: 'Invalid admin token' });
  }
}

async function checkUserAccess(userId) {
  const { data } = await supabase
    .from('sessions')
    .select('expires_at')
    .eq('user_id', userId)
    .gt('expires_at', new Date().toISOString())
    .order('expires_at', { ascending: false })
    .limit(1)
    .single();
  return data ? { hasAccess: true, expiresAt: data.expires_at } : { hasAccess: false };
}

async function getMpesaToken() {
  const auth = Buffer.from(
    `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
  ).toString('base64');
  try {
    const { data } = await axios.get(
      'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
      { headers: { Authorization: `Basic ${auth}` } }
    );
    return data.access_token;
  } catch (e) {
    console.error('Token error:', e.response?.data || e.message);
    throw e;
  }
}
  const auth = Buffer.from(
    `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
  ).toString('base64');
  const { data } = await axios.get(
    'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
    { headers: { Authorization: `Basic ${auth}` } }
  );
  return data.access_token;
}

async function stkPush({ phone, amount }) {
  const token = await getMpesaToken();
  const timestamp = new Date().toISOString().replace(/[-T:.Z]/g, '').slice(0, 14);
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;
  const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
  const { data } = await axios.post(
    'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
    {
      BusinessShortCode: shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: amount,
      PartyA: phone,
      PartyB: shortcode,
      PhoneNumber: phone,
      CallBackURL: `${process.env.BACKEND_URL}/api/pay/callback`,
      AccountReference: 'ElimuPay',
      TransactionDesc: '30min Video Access'
    },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return data;
}

app.post('/api/register', async (req, res) => {
  try {
    const { name, username, password } = req.body;
    if (!name || !username || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
    const { data: existing, error: checkError } = await supabase
      .from('users').select('id').eq('username', username.toLowerCase()).single();
    if (checkError && checkError.code !== 'PGRST116') {
      return res.status(500).json({ error: 'Database error' });
    }
    if (existing) return res.status(409).json({ error: 'Username already taken' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const { error } = await supabase.from('users').insert({
      name,
      username: username.toLowerCase(),
      password: hashedPassword
    });
    if (error) return res.status(500).json({ error: 'Registration failed' });
    res.json({ message: 'Account created successfully' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = getIP(req);
    const userAgent = req.headers['user-agent'] || '';
    if (!username || !password) return res.status(400).json({ error: 'All fields required' });
    const { data: user } = await supabase
      .from('users').select('*').eq('username', username.toLowerCase()).single();
    const success = user && (await bcrypt.compare(password, user.password));
    await supabase.from('login_attempts').insert({
      username: username.toLowerCase(),
      ip,
      user_agent: userAgent,
      status: success ? 'success' : 'failed'
    });
    if (!success) return res.status(401).json({ error: 'Invalid username or password' });
    const token = signToken({ userId: user.id, username: user.username });
    const access = await checkUserAccess(user.id);
    res.json({ token, hasAccess: access.hasAccess, expiresAt: access.expiresAt });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/check-access', verifyToken, async (req, res) => {
  try {
    const access = await checkUserAccess(req.user.userId);
    res.json(access);
  } catch (err) {
    res.status(500).json({ error: 'Check access failed' });
  }
});

app.post('/api/pay/initiate', verifyToken, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
    const result = await stkPush({ phone, amount: 10 });
    if (result.ResponseCode !== '0') {
      return res.status(400).json({ error: result.ResponseDescription || 'M-Pesa request failed' });
    }
    await supabase.from('payments').insert({
      user_id: req.user.userId,
      username: req.user.username,
      phone,
      amount: 10,
      checkout_request_id: result.CheckoutRequestID,
      status: 'pending'
    });
    res.json({ message: 'STK push sent', checkoutRequestId: result.CheckoutRequestID });
  } catch (e) {
    console.error('STK push error:', e.message);
    console.error('STK push details:', e.response?.data);
    res.status(500).json({ error: 'Payment initiation failed' });
  }
    
  
});

app.post('/api/pay/callback', async (req, res) => {
  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) return res.sendStatus(200);
    const checkoutRequestId = body.CheckoutRequestID;
    const resultCode = body.ResultCode;
    if (resultCode === 0) {
      const items = body.CallbackMetadata?.Item || [];
      const getItem = name => items.find(i => i.Name === name)?.Value;
      const mpesaRef = getItem('MpesaReceiptNumber');
      const amount = getItem('Amount');
      await supabase.from('payments')
        .update({ status: 'paid', mpesa_ref: mpesaRef, amount })
        .eq('checkout_request_id', checkoutRequestId);
      const { data: payment } = await supabase
        .from('payments').select('user_id').eq('checkout_request_id', checkoutRequestId).single();
      if (payment) {
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        await supabase.from('sessions').insert({
          user_id: payment.user_id,
          expires_at: expiresAt
        });
      }
    } else {
      await supabase.from('payments')
        .update({ status: 'failed' })
        .eq('checkout_request_id', checkoutRequestId);
    }
    res.sendStatus(200);
  } catch (err) {
    console.error('Callback error:', err);
    res.sendStatus(200);
  }
});

app.get('/api/pay/status/:checkoutRequestId', verifyToken, async (req, res) => {
  try {
    const { checkoutRequestId } = req.params;
    const { data } = await supabase
      .from('payments')
      .select('status, mpesa_ref, amount')
      .eq('checkout_request_id', checkoutRequestId)
      .single();
    if (!data) return res.status(404).json({ error: 'Payment not found' });
    res.json(data);
  } catch (err) {
    console.error('Status error:', err);
    res.status(500).json({ error: 'Status check failed' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ElimuPay server running on port ${PORT}`);
});
