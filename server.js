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
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
