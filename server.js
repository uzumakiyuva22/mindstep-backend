// server.js
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const sqlite3 = require('sqlite3').verbose();

// CONFIG
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const TOTAL_LESSONS = process.env.TOTAL_LESSONS ? parseInt(process.env.TOTAL_LESSONS) : 4;

// DIRECTORIES
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(PUBLIC_DIR, 'uploads');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// MULTER
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /\.(png|jpe?g|gif|webp)$/i;
    if (!allowed.test(file.originalname)) return cb(new Error('Only image files allowed'));
    cb(null, true);
  }
});

// DATABASE (sqlite3)
const DB_PATH = path.join(__dirname, 'users.db');
const db = new sqlite3.Database(DB_PATH);

// promisify helpers
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// MIGRATION / SCHEMA
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON;');
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      display_name TEXT,
      image TEXT,
      percentage INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      display_name TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS completions (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      lesson_id TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, lesson_id)
    );
  `);
});

// create default admin if not exists
(async function ensureDefaultAdmin() {
  try {
    const adminName = process.env.DEFAULT_ADMIN_USER || 'admin';
    const adminPass = process.env.DEFAULT_ADMIN_PASS || 'admin123';
    const row = await get(`SELECT * FROM admins WHERE username = ?`, [adminName]);
    if (!row) {
      const hashed = bcrypt.hashSync(adminPass, 10);
      await run(`INSERT INTO admins (id, username, password, display_name) VALUES (?, ?, ?, ?)`, [
        uuidv4(),
        adminName,
        hashed,
        'Administrator'
      ]);
      console.log(`[INIT] Default admin created -> username: ${adminName}`);
    } else {
      console.log('[INIT] Admin exists, skipping default creation.');
    }
  } catch (err) {
    console.error('Default admin error:', err);
  }
})();

// helpers
function removePassword(userRecord) {
  if (!userRecord) return userRecord;
  const { password, ...rest } = userRecord;
  return rest;
}
async function computeAndUpdatePercentage(userId, totalLessons = TOTAL_LESSONS) {
  const row = await get(`SELECT COUNT(*) as cnt FROM completions WHERE user_id = ?`, [userId]);
  const completed = row ? row.cnt : 0;
  const percent = totalLessons > 0 ? Math.round((completed / totalLessons) * 100) : 0;
  await run(`UPDATE users SET percentage = ? WHERE id = ?`, [percent, userId]);
  return { completed, percent };
}

// EXPRESS
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use('/uploads', express.static(UPLOADS_DIR));

// simple logger
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.url);
  next();
});

// auth helpers
function signAdminToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}
function verifyAdminToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (_) {
    return null;
  }
}
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing admin token' });
  const token = auth.slice(7);
  const decoded = verifyAdminToken(token);
  if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
  req.admin = decoded;
  next();
}

// ROUTES

// health
app.get('/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body || {};
    if (!username || !email || !password) return res.status(400).json({ error: 'username, email and password required' });

    const existsUser = await get(`SELECT 1 FROM users WHERE username = ?`, [username]);
    if (existsUser) return res.status(400).json({ error: 'username already exists' });

    const existsEmail = await get(`SELECT 1 FROM users WHERE email = ?`, [email]);
    if (existsEmail) return res.status(400).json({ error: 'email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const display_name = displayName || username;
    await run(
      `INSERT INTO users (id, username, email, password, display_name, image, percentage) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, username, email, hashed, display_name, null, 0]
    );

    const user = await get(`SELECT id, username, email, display_name, image, percentage, created_at FROM users WHERE id = ?`, [id]);
    res.json({ success: true, user });
  } catch (err) {
    console.error('signup err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: 'usernameOrEmail and password required' });

    let user = await get(`SELECT * FROM users WHERE username = ?`, [usernameOrEmail]);
    if (!user) user = await get(`SELECT * FROM users WHERE email = ?`, [usernameOrEmail]);
    if (!user) return res.status(400).json({ error: 'user not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const safe = removePassword(user);
    res.json({ success: true, user: safe });
  } catch (err) {
    console.error('login err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const admin = await get(`SELECT * FROM admins WHERE username = ?`, [username]);
    if (!admin) return res.status(400).json({ error: 'admin not found' });

    const ok = await bcrypt.compare(password, admin.password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const token = signAdminToken({ id: admin.id, username: admin.username, display_name: admin.display_name });
    res.json({ success: true, token });
  } catch (err) {
    console.error('admin login err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// admin users list
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const rows = await all(`SELECT id, username, email, display_name, image, percentage, created_at FROM users ORDER BY created_at DESC`);
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// delete completion
app.delete('/api/admin/completion', requireAdmin, async (req, res) => {
  try {
    const { id, userId, lessonId } = req.body || {};
    if (id) {
      const info = await run(`DELETE FROM completions WHERE id = ?`, [id]);
      return res.json({ success: true, deleted: info.changes });
    }
    if (userId && lessonId) {
      const info = await run(`DELETE FROM completions WHERE user_id = ? AND lesson_id = ?`, [userId, lessonId]);
      return res.json({ success: true, deleted: info.changes });
    }
    return res.status(400).json({ error: 'provide id OR (userId and lessonId)' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// upload image
app.post('/api/upload-image', upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file uploaded' });
    const urlPath = `/uploads/${path.basename(req.file.path)}`;
    res.json({ success: true, path: urlPath, filename: path.basename(req.file.path) });
  } catch (err) {
    console.error('upload err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// lesson complete
app.post('/api/complete', async (req, res) => {
  try {
    const { userId, lessonId, totalLessons } = req.body || {};
    if (!userId || !lessonId) return res.status(400).json({ error: 'userId and lessonId required' });

    const id = uuidv4();
    // insert or ignore using SQL trick: INSERT OR IGNORE
    await run(`INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)`, [id, userId, lessonId]);

    const stats = await computeAndUpdatePercentage(userId, totalLessons ? parseInt(totalLessons) : TOTAL_LESSONS);

    res.json({ success: true, completedLessons: stats.completed, percentage: stats.percent });
  } catch (err) {
    console.error('complete err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// debug
app.get('/api/debug', requireAdmin, async (req, res) => {
  try {
    const usersCount = (await get(`SELECT COUNT(*) as c FROM users`)).c;
    const adminsCount = (await get(`SELECT COUNT(*) as c FROM admins`)).c;
    const completionsCount = (await get(`SELECT COUNT(*) as c FROM completions`)).c;
    res.json({ ok: true, usersCount, adminsCount, completionsCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// optional run-code placeholder
app.post('/api/run', async (req, res) => {
  try {
    const { language, code } = req.body || {};
    if (!language || !code) return res.status(400).json({ error: 'language and code required' });

    const dockerSock = '/var/run/docker.sock';
    if (!fs.existsSync(dockerSock)) {
      return res.status(400).json({
        success: false,
        error: 'Docker unavailable on this host. Run-code feature requires Docker; it is not available here.'
      });
    }
    return res.status(501).json({ success: false, error: 'Run-code not implemented on this deployment.' });
  } catch (err) {
    console.error('run err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// serve frontend files if present
app.get('/', (req, res) => {
  const file = path.join(PUBLIC_DIR, 'MainPage.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send('MainPage not found. Upload your public/MainPage.html');
});
app.get('/course.html', (req, res) => {
  const file = path.join(PUBLIC_DIR, 'course.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send('course.html not found.');
});
app.get('/lesson.html', (req, res) => {
  const file = path.join(PUBLIC_DIR, 'lesson.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send('lesson.html not found.');
});

// 404
app.use((req, res) => {
  if (req.accepts('html')) {
    const f = path.join(PUBLIC_DIR, '404.html');
    if (fs.existsSync(f)) return res.status(404).sendFile(f);
    return res.status(404).send('404 - Not found');
  }
  res.status(404).json({ error: 'Not found' });
});

// error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: err.message || 'server error' });
});

// start
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT} (pid ${process.pid})`);
});
