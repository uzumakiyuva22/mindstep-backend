require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');

const mongoose = require('mongoose');

const PUBLIC_DIR = path.join(__dirname, 'public'); // frontend put here

// connect mongo
mongoose.set('strictQuery', false);
mongoose.connect(process.env.MONGO_URI)
  .then(()=> console.log('✔ MongoDB connected'))
  .catch(err => { console.error('Mongo connect failed:', err.message || err); process.exit(1); });

const app = express();
app.use(cors());
app.use(express.json({limit:'25mb'}));
app.use(express.urlencoded({ extended:true }));
app.use(express.static(PUBLIC_DIR));

// routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api', require('./routes/public')); // public endpoints
app.use('/api', require('./routes/task')); // task endpoints

// seed (non-blocking)
require('./seeds/seed')().catch(e => console.error('Seed error:', e));

app.get('/health', (req,res)=> res.json({ ok:true, ts: Date.now() }));
app.get('/', (req,res)=>{
  const f = path.join(PUBLIC_DIR,'LoginPage.html');
  if (require('fs').existsSync(f)) return res.sendFile(f);
  res.send('<h3>MindStep backend</h3><p>Drop frontend into /public</p>');
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, ()=> console.log(`🔥 Server listening on http://localhost:${PORT}`));
