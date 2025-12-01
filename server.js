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
const Database = require('better-sqlite3');

// CONFIG
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const TOTAL_LESSONS = process.env.TOTAL_LESSONS ? parseInt(process.env.TOTAL_LESSONS) : 4;

// DIRECTORIES
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(PUBLIC_DIR, 'uploads');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// MULTER (image uploads)
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

// DATABASE using better-sqlite3 (synchronous API)
const DB_PATH = path.join(__dirname, 'users.db');
const db = new Database(DB_PATH);

// MIGRATION / SCHEMA (run once, safe to call repeatedly)
db.pragma('foreign_keys = ON');
db.exec(`
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

  CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    display_name TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS completions (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    lesson_id TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, lesson_id)
  );
`);

// prepare statements (reusable)
const insertUserStmt = db.prepare(`INSERT INTO users (id, username, email, password, display_name, image, percentage) VALUES (?, ?, ?, ?, ?, ?, ?)`);
const findUserByUsernameStmt = db.prepare(`SELECT * FROM users WHERE username = ?`);
const findUserByEmailStmt = db.prepare(`SELECT * FROM users WHERE email = ?`);
const getUserByIdStmt = db.prepare(`SELECT id, username, email, display_name, image, percentage, created_at FROM users WHERE id = ?`);
const updateUserPercentageStmt = db.prepare(`UPDATE users SET percentage = ? WHERE id = ?`);

const insertAdminStmt = db.prepare(`INSERT INTO admins (id, username, password, display_name) VALUES (?, ?, ?, ?)`);
const findAdminByUsernameStmt = db.prepare(`SELECT * FROM admins WHERE username = ?`);

const insertCompletionStmt = db.prepare(`INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)`);
const countCompletionsForUserStmt = db.prepare(`SELECT COUNT(*) as cnt FROM completions WHERE user_id = ?`);
const deleteCompletionByIdStmt = db.prepare(`DELETE FROM completions WHERE id = ?`);
const deleteCompletionByUserLessonStmt = db.prepare(`DELETE FROM completions WHERE user_id = ? AND lesson_id = ?`);

// Default admin creation (runs once)
(function ensureDefaultAdmin() {
  try {
    const adminName = process.env.DEFAULT_ADMIN_USER || 'admin';
    const adminPass = process.env.DEFAULT_ADMIN_PASS || 'admin123';
    const exists = findAdminByUsernameStmt.get(adminName);
    if (!exists) {
      const hashed = bcrypt.hashSync(adminPass, 10);
      insertAdminStmt.run(uuidv4(), adminName, hashed, 'Administrator');
      console.log(`[INIT] Default admin created -> username: ${adminName}`);
    } else {
      console.log('[INIT] Admin already exists, skipping default creation.');
    }
  } catch (err) {
    console.error('Error ensuring default admin:', err);
  }
})();

// helpers
function removePassword(userRecord) {
  if (!userRecord) return userRecord;
  const { password, ...rest } = userRecord;
  return rest;
}
function computeAndUpdatePercentage(userId, totalLessons = TOTAL_LESSONS) {
  const row = countCompletionsForUserStmt.get(userId);
  const completed = row ? row.cnt : 0;
  const percent = totalLessons > 0 ? Math.round((completed / totalLessons) * 100) : 0;
  updateUserPercentageStmt.run(percent, userId);
  return { completed, percent };
}

// EXPRESS app
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR)); // serve static files
app.use('/uploads', express.static(UPLOADS_DIR)); // serve uploads

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
  } catch (e) {
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
app.post('/api/signup', (req, res) => {
  try {
    const { username, email, password, displayName } = req.body || {};
    if (!username || !email || !password) return res.status(400).json({ error: 'username, email and password required' });

    if (findUserByUsernameStmt.get(username)) return res.status(400).json({ error: 'username already exists' });
    if (findUserByEmailStmt.get(email)) return res.status(400).json({ error: 'email already exists' });

    const hashed = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    const display_name = displayName || username;
    insertUserStmt.run(id, username, email, hashed, display_name, null, 0);

    const user = getUserByIdStmt.get(id);
    return res.json({ success: true, user });
  } catch (err) {
    console.error('signup err', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// login
app.post('/api/login', (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: 'usernameOrEmail and password required' });

    let user = findUserByUsernameStmt.get(usernameOrEmail);
    if (!user) user = findUserByEmailStmt.get(usernameOrEmail);
    if (!user) return res.status(400).json({ error: 'user not found' });

    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const safe = removePassword(user);
    return res.json({ success: true, user: safe });
  } catch (err) {
    console.error('login err', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// admin login
app.post('/api/admin/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const admin = findAdminByUsernameStmt.get(username);
    if (!admin) return res.status(400).json({ error: 'admin not found' });

    const ok = bcrypt.compareSync(password, admin.password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const token = signAdminToken({ id: admin.id, username: admin.username, display_name: admin.display_name });
    return res.json({ success: true, token });
  } catch (err) {
    console.error('admin login err', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// admin users list
app.get('/api/admin/users', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`SELECT id, username, email, display_name, image, percentage, created_at FROM users ORDER BY created_at DESC`).all();
    return res.json({ success: true, users: rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server error' });
  }
});

// delete completion
app.delete('/api/admin/completion', requireAdmin, (req, res) => {
  try {
    const { id, userId, lessonId } = req.body || {};
    if (id) {
      const info = deleteCompletionByIdStmt.run(id);
      return res.json({ success: true, deleted: info.changes });
    }
    if (userId && lessonId) {
      const info = deleteCompletionByUserLessonStmt.run(userId, lessonId);
      return res.json({ success: true, deleted: info.changes });
    }
    return res.status(400).json({ error: 'provide id OR (userId and lessonId)' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server error' });
  }
});

// upload image
app.post('/api/upload-image', upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file uploaded' });
    const urlPath = `/uploads/${path.basename(req.file.path)}`;
    return res.json({ success: true, path: urlPath, filename: path.basename(req.file.path) });
  } catch (err) {
    console.error('upload err', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// lesson complete
app.post('/api/complete', (req, res) => {
  try {
    const { userId, lessonId, totalLessons } = req.body || {};
    if (!userId || !lessonId) return res.status(400).json({ error: 'userId and lessonId required' });

    const id = uuidv4();
    insertCompletionStmt.run(id, userId, lessonId);

    const stats = computeAndUpdatePercentage(userId, totalLessons ? parseInt(totalLessons) : TOTAL_LESSONS);
    return res.json({ success: true, completedLessons: stats.completed, percentage: stats.percent });
  } catch (err) {
    console.error('complete err', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// debug route (admin only)
app.get('/api/debug', requireAdmin, (req, res) => {
  try {
    const usersCount = db.prepare(`SELECT COUNT(*) as c FROM users`).get().c;
    const adminsCount = db.prepare(`SELECT COUNT(*) as c FROM admins`).get().c;
    const completionsCount = db.prepare(`SELECT COUNT(*) as c FROM completions`).get().c;
    return res.json({ ok: true, usersCount, adminsCount, completionsCount });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server error' });
  }
});

// optional run-code placeholder
app.post('/api/run', (req, res) => {
  return res.status(501).json({ success: false, error: 'Run-code not implemented on this deployment.' });
});

// serve frontend pages (LoginPage as homepage)
app.get('/', (req, res) => {
  const file = path.join(PUBLIC_DIR, 'LoginPage.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send('LoginPage not found. Put public/LoginPage.html');
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
