// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
// Ensure your .env file has SUPABASE_URL and SUPABASE_SERVICE_KEY
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.use(express.json());
app.use(cors());

// 1. Static Files: Make sure this points to your 'public' folder correctly
const publicPath = path.join(__dirname, 'public');
console.log("Serving static files from:", publicPath);
app.use(express.static(publicPath));

// 2. Public API Route
app.get('/api/videos', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load videos' });
  }
  app.post('/api/admin/login', (req, res) => {
  res.json({
    success: true,
    token: 'test-token'
  });
});
});
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

app.use(express.json());
app.use(cors());

const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

/* =========================
   VIDEOS
========================= */
app.get('/api/videos', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      error: 'Failed to load videos'
    });
  }
});

/* =========================
   ADMIN LOGIN
========================= */
app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        success: false,
        message: 'Password required'
      });
    }

    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

    if (password === ADMIN_PASSWORD) {
      return res.json({
        success: true,
        message: 'Login successful'
      });
    }

    return res.status(401).json({
      success: false,
      message: 'Invalid password'
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      error: 'Password required'
    });
  }

  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({
      error: 'Invalid password'
    });
  }

  res.json({
    success: true,
    token: 'admin-token'
  });
});
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
