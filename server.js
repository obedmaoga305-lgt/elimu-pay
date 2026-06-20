// ╔══════════════════════════════════════════════════════╗
// ║              ElimuFree — Backend Server              ║
// ║         Educational Video Platform · Kenya           ║
// ╚══════════════════════════════════════════════════════╝

require('dotenv').config();

const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const path         = require('path');
const helmet       = require('helmet');
const morgan       = require('morgan');
const rateLimit    = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// ─────────────────────────────────────────
//  App & Middleware
// ─────────────────────────────────────────
const app = express();

app.set('trust proxy', 1); // Trust Render/Railway reverse proxy

// Force HTTPS in production
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === 'production' &&
    req.headers['x-forwarded-proto'] !== 'https'
  ) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

app.use(express.json());
app.use(cors({ origin: '*' }));
app.use(morgan('dev'));
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// ─────────────────────────────────────────
//  Rate Limiters
// ─────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many requests. Please wait 15 minutes and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many requests. Please slow down.' },
});

app.use('/api/login',           authLimiter);
app.use('/api/register',        authLimiter);
app.use('/api/',                generalLimiter);

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

function sanitize(str) {
  return typeof str === 'string' ? str.trim() : str;
}

// Generate dummy email for Supabase Auth to bypass email requirements
const generateDummyEmail = (username) => `${username.toLowerCase().replace(/[^a-z0-9]/g, '')}@elimufree.local`;

// ─────────────────────────────────────────
//  Middleware — Auth Guards
// ─────────────────────────────────────────
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

// ═══════════════════════════════════════════════════════
//  ROUTES — AUTH (NO EMAIL REQUIRED)
// ═══════════════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const username = sanitize(req.body.username);
    const password = sanitize(req.body.password);

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const dummyEmail = generateDummyEmail(username);

    // Check if username already exists
    const { data: existing, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('email', dummyEmail)
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      return res.status(500).json({ error: 'Database error. Please try again.' });
    }
    if (existing) {
      return res.status(409).json({ error: 'This username is already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Insert into public.users table
    const { error: insertError } = await supabase.from('users').insert({
      name: username, 
      email: dummyEmail, // Store dummy email so the database constraint doesn't break
      password: hashedPassword,
    });

    if (insertError) {
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
    const username  = sanitize(req.body.username);
    const password  = sanitize(req.body.password);
    const ip        = getIP(req);
    const userAgent = req.headers['user-agent'] || '';

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const dummyEmail = generateDummyEmail(username);

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', dummyEmail)
      .single();

    const success = user && !user.is_banned && (await bcrypt.compare(password, user.password));

    await supabase.from('login_attempts').insert({
      email: dummyEmail, ip, user_agent: userAgent,
      status: success ? 'success' : 'failed',
    });

    if (!success) {
      if (user?.is_banned) {
        return res.status(403).json({ error: 'This account has been suspended. Contact support.' });
      }
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token  = signToken({ userId: user.id, username: user.name });

    res.json({
      token,
      hasAccess: true, // Always true for ElimuFree
      name: user.name,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — VIDEOS (100% FREE)
// ═══════════════════════════════════════════════════════

// GET /api/videos (Publicly accessible, no token required)
app.get('/api/videos', async (req, res) => {
  try {
    const { subject, grade } = req.query;
    let query = supabase
      .from('videos')
      .select('id, title, description, url, thumbnail, subject, grade, duration')
      .or('is_active.eq.true,is_active.is.null')
      .order('created_at', { ascending: false });

    if (subject) query = query.eq('subject', subject);
    if (grade)   query = query.eq('grade', grade);

    const { data, error } = await query;
    if (error) throw error;

    res.json({ videos: data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load videos' });
  }
});

// POST /api/videos/:id/view (Publicly accessible, count views)
app.post('/api/videos/:id/view', async (req, res) => {
  try {
    const { data: video } = await supabase
      .from('videos')
      .select('views')
      .eq('id', req.params.id)
      .single();

    if (video) {
      await supabase
        .from('videos')
        .update({ views: (video.views || 0) + 1 })
        .eq('id', req.params.id);
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to record view' });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTES — ADMIN (RETAINED)
// ═══════════════════════════════════════════════════════

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

app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admin_stats').select('*').single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, name, email, is_banned, created_at')
      .order('created_at', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json({ users: data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.post('/api/admin/users/:id/ban', verifyAdmin, async (req, res) => {
  try {
    const { ban } = req.body;
    const { error } = await supabase
      .from('users')
      .update({ is_banned: !!ban })
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ message: ban ? 'User banned successfully' : 'User unbanned successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

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

app.get('/api/admin/all-videos', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ videos: data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load videos' });
  }
});

app.post('/api/admin/videos', verifyAdmin, async (req, res) => {
  try {
    const { title, description, url, thumbnail, subject, grade, duration } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'Title and URL are required' });

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
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    service:   'ElimuFree API'
  });
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
  console.log(`\n  ╔═══════════════════════════════════════════╗`);
  console.log(`  ║   ElimuFree server is running 🚀          ║`);
  console.log(`  ║   http://localhost:${PORT}                   ║`);
  console.log(`  ║   Status: 100% Free, No Email Required    ║`);
  console.log(`  ╚═══════════════════════════════════════════╝\n`);
});
