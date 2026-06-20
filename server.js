require('dotenv').config();
app.get('/test', (req, res) => {
  res.send('TEST ROUTE WORKS');
});
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

/* =========================
   STATIC FILES
========================= */
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

/* =========================
   HEALTH CHECK
========================= */
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'ElimuPay Backend Running'
  });
});

/* =========================
   PUBLIC VIDEOS API
========================= */
app.get('/api/videos', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .eq('is_active', true)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (error) {
    console.error('Videos Error:', error);

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
        error: 'Password is required'
      });
    }

    if (password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({
        success: false,
        error: 'Invalid password'
      });
    }

    return res.json({
      success: true,
      token: 'admin-token'
    });

  } catch (error) {
    console.error('Login Error:', error);

    return res.status(500).json({
      success: false,
      error: 'Server error'
    });
  }
});

/* =========================
   ADMIN STATS
========================= */
app.get('/api/admin/stats', async (req, res) => {
  try {
    const { count: videoCount } = await supabase
      .from('videos')
      .select('*', { count: 'exact', head: true });

    res.json({
      total_users: 0,
      total_revenue: 0,
      total_paid: 0,
      pending_payments: 0,
      active_videos: videoCount || 0,
      active_sessions: 1
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Failed to load stats'
    });
  }
});

/* =========================
   ADMIN USERS
========================= */
app.get('/api/admin/users', async (req, res) => {
  res.json({
    users: []
  });
});

/* =========================
   ADMIN PAYMENTS
========================= */
app.get('/api/admin/payments', async (req, res) => {
  res.json({
    payments: []
  });
});

/* =========================
   ADMIN ATTEMPTS
========================= */
app.get('/api/admin/attempts', async (req, res) => {
  res.json({
    attempts: []
  });
});

/* =========================
   ADMIN ALL VIDEOS
========================= */
app.get('/api/admin/all-videos', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({
      videos: data || []
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Failed to load videos'
    });
  }
});

/* =========================
   ADD VIDEO
========================= */
app.post('/api/admin/videos', async (req, res) => {
  try {
    const {
      title,
      url,
      subject,
      grade,
      thumbnail,
      duration,
      description
    } = req.body;

    const { data, error } = await supabase
      .from('videos')
      .insert([
        {
          title,
          url,
          subject,
          grade,
          thumbnail,
          duration,
          description,
          is_active: true
        }
      ])
      .select();

    if (error) throw error;

    res.json({
      success: true,
      video: data
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Failed to add video'
    });
  }
});

/* =========================
   DELETE VIDEO
========================= */
app.delete('/api/admin/videos/:id', async (req, res) => {
  try {
    const { error } = await supabase
      .from('videos')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;

    res.json({
      success: true
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Failed to delete video'
    });
  }
});

/* =========================
   BAN USER PLACEHOLDER
========================= */
app.post('/api/admin/users/:id/ban', async (req, res) => {
  res.json({
    success: true
  });
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
