require('dotenv').config();

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
app.use(express.static(path.join(__dirname, 'public')));

/* =========================
   TEST ROUTE
========================= */
app.get('/test', (req, res) => {
  res.send('TEST ROUTE WORKS');
});

/* =========================
   HOME
========================= */
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'ElimuPay Backend Running'
  });
});

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
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: 'Failed to load videos'
    });
  }
});

/* =========================
   ADMIN LOGIN
========================= */
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      success: false,
      error: 'Password required'
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
});

/* =========================
   ADMIN STATS
========================= */
app.get('/api/admin/stats', async (req, res) => {
  try {
    const { count } = await supabase
      .from('videos')
      .select('*', { count: 'exact', head: true });

    res.json({
      active_videos: count || 0
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to load stats'
    });
  }
});

/* =========================
   ALL VIDEOS
========================= */
app.get('/api/admin/all-videos', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({
      videos: data
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to load videos'
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
