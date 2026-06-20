// ElimuFree — Backend Server
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.use(express.json());
app.use(cors());

// Public Route: Fetch all active videos
app.get('/api/videos', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .or('is_active.eq.true,is_active.is.null')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json({ videos: data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load videos' });
  }
});

// View counter route
app.post('/api/videos/:id/view', async (req, res) => {
  try {
    const { data: video } = await supabase.from('videos').select('views').eq('id', req.params.id).single();
    if (video) {
      await supabase.from('videos').update({ views: (video.views || 0) + 1 }).eq('id', req.params.id);
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to record' }); }
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
