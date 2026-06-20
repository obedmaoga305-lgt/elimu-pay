require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();

/* =========================================
   1. MIDDLEWARE & CONFIGURATION
========================================= */
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Verify Supabase keys are present at startup
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error("🔥 CRITICAL: Supabase Environment Variables missing!");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_render';

/* =========================================
   2. AUTHENTICATION GATES (MIDDLEWARE)
========================================= */
const verifyAdmin = (req, res, next) => {
  // Accepts token via Header (Bearer), custom header, or URL query param
  const token = req.headers.authorization?.split(' ')[1] 
    || req.headers['x-auth-token'] 
    || req.query.token;

  // LEGACY ESCAPE HATCH: Keeps your current admin.html working instantly
  if (token === 'admin-token') return next();

  if (!token) {
    return res.status(401).json({ success: false, error: 'Access Denied: No Token' });
  }

  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ success: false, error: 'Session expired or invalid' });
  }
};

/* =========================================
   3. PUBLIC ROUTES
========================================= */
app.get('/', (req, res) => {
  res.status(200).json({ success: true, status: 'ElimuPay v2.0 Online' });
});

app.get('/test', (req, res) => {
  res.status(200).send('TEST ROUTE WORKS PERFECTLY');
});

app.get('/api/videos', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.status(200).json(data);
  } catch (error) {
    console.error('Video Fetch Error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to load public videos' });
  }
});

/* =========================================
   4. ADMIN LOGIN ROUTE
========================================= */
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, error: 'Password required' });
  }

  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: 'Incorrect Admin Password' });
  }

  // Issue real JWT valid for 8 hours
  const token = jwt.sign({ role: 'administrator' }, JWT_SECRET, { expiresIn: '8h' });

  return res.status(200).json({
    success: true,
    token: token // Frontend should capture and store this
  });
});

/* =========================================
   5. PROTECTED ADMIN DATA ROUTES 
========================================= */

// STATS
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const { count: vCount } = await supabase.from('videos').select('*', { count: 'exact', head: true });
    
    // Safe-fallbacks: won't crash if these tables don't exist yet
    const uCount = await supabase.from('users').select('*', { count: 'exact', head: true }).then(r=>r.count).catch(()=>0);
    const pCount = await supabase.from('payments').select('*', { count: 'exact', head: true }).then(r=>r.count).catch(()=>0);

    res.status(200).json({
      success: true,
      active_videos: vCount || 0,
      total_users: uCount || 0,
      total_payments: pCount || 0
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to calculate server stats' });
  }
});

// ALL VIDEOS (ADMIN VIEW)
app.get('/api/admin/all-videos', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('videos').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.status(200).json({ success: true, videos: data });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to load video ledger' });
  }
});

// USERS
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').limit(50);
    if (error) throw error;
    res.status(200).json({ success: true, users: data });
  } catch (error) {
    res.status(200).json({ success: true, users: [], warning: "Table 'users' uninitialized" });
  }
});

// PAYMENTS
app.get('/api/admin/payments', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('payments').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.status(200).json({ success: true, payments: data });
  } catch (error) {
    res.status(200).json({ success: true, payments: [], warning: "Table 'payments' uninitialized" });
  }
});

// ATTEMPTS
app.get('/api/admin/attempts', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('attempts').select('*').limit(50);
    if (error) throw error;
    res.status(200).json({ success: true, attempts: data });
  } catch (error) {
    res.status(200).json({ success: true, attempts: [], warning: "Table 'attempts' uninitialized" });
  }
});

/* =========================================
   6. CATCH-ALL 404 HANDLER
========================================= */
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    error: `The endpoint [${req.method}] '${req.originalUrl}' does not exist on this server.` 
  });
});

/* =========================================
   7. SERVER IGNITION
========================================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Production Server running on Port ${PORT}`);
});
