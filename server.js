/**
 * server.js

 */

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



const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const TOTAL_LESSONS = process.env.TOTAL_LESSONS ? parseInt(process.env.TOTAL_LESSONS) : 4; // used to compute percentage

// --------------------- Ensure directories ---------------------
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(PUBLIC_DIR, 'uploads');

if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// --------------------- Multer (image upload) ---------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    const allowed = /\.(png|jpe?g|gif|webp)$/i;
    if (!allowed.test(file.originalname)) return cb(new Error('Only image files allowed'));
    cb(null, true);
  }
});

// --------------------- Database setup ---------------------
const DB_PATH = path.join(__dirname, 'users.db');
const db = new Database(DB_PATH);

// Run migrations / create tables if not exist
db.exec(`
  PRAGMA foreign_keys = ON;

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

// Prepared statements
const stmtInsertUser = db.prepare(`INSERT INTO users (id, username, email, password, display_name, image, percentage) VALUES (@id,@username,@email,@password,@display_name,@image,@percentage)`);
const stmtFindUserByUsername = db.prepare(`SELECT * FROM users WHERE username = ?`);
const stmtFindUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`);
const stmtGetUserById = db.prepare(`SELECT id, username, email, display_name, image, percentage, created_at FROM users WHERE id = ?`);
const stmtUpdateUserPercentage = db.prepare(`UPDATE users SET percentage = @percentage WHERE id = @id`);

const stmtInsertAdmin = db.prepare(`INSERT INTO admins (id, username, password, display_name) VALUES (@id,@username,@password,@display_name)`);
const stmtFindAdminByUsername = db.prepare(`SELECT * FROM admins WHERE username = ?`);

const stmtInsertCompletion = db.prepare(`INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (@id,@user_id,@lesson_id)`);
const stmtCountCompletionsForUser = db.prepare(`SELECT COUNT(*) as cnt FROM completions WHERE user_id = ?`);
const stmtDeleteCompletion = db.prepare(`DELETE FROM completions WHERE id = ?`);
const stmtDeleteCompletionByUserLesson = db.prepare(`DELETE FROM completions WHERE user_id = ? AND lesson_id = ?`);

// --------------------- Default admin creation (runs once) ---------------------
(function ensureDefaultAdmin() {
  try {
    const adminName = process.env.DEFAULT_ADMIN_USER || 'admin';
    const adminPass = process.env.DEFAULT_ADMIN_PASS || 'admin123'; // change in prod
    const exists = stmtFindAdminByUsername.get(adminName);
    if (!exists) {
      const hashed = bcrypt.hashSync(adminPass, 10);
      stmtInsertAdmin.run({ id: uuidv4(), username: adminName, password: hashed, display_name: 'Administrator' });
      console.log(`[INIT] Default admin created -> username: ${adminName}`);
    } else {
      console.log('[INIT] Admin already exists, skipping default creation.');
    }
  } catch (err) {
    console.error('Error ensuring default admin:', err);
  }
})();

// --------------------- Helpers ---------------------
function removePassword(userRecord) {
  if (!userRecord) return userRecord;
  const { password, ...rest } = userRecord;
  return rest;
}

function computeAndUpdatePercentage(userId, totalLessons = TOTAL_LESSONS) {
  const row = stmtCountCompletionsForUser.get(userId);
  const completed = row ? row.cnt : 0;
  const percent = totalLessons > 0 ? Math.round((completed / totalLessons) * 100) : 0;
  stmtUpdateUserPercentage.run({ percentage: percent, id: userId });
  return { completed, percent };
}

// --------------------- Express app ---------------------
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR)); // serve static files from /public
// serve uploaded images explicitly via /uploads
app.use('/uploads', express.static(UPLOADS_DIR));

// Basic logger (dev)
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// --------------------- Authentication helpers ---------------------
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

// Admin middleware
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing admin token' });
  const token = auth.slice(7);
  const decoded = verifyAdminToken(token);
  if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
  req.admin = decoded;
  next();
}

// --------------------- Routes ---------------------

// Health
app.get('/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ---------- User signup ----------
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body || {};
    if (!username || !email || !password) return res.status(400).json({ error: 'username, email and password required' });

    // check duplicates
    if (stmtFindUserByUsername.get(username)) return res.status(400).json({ error: 'username already exists' });
    if (stmtFindUserByEmail.get(email)) return res.status(400).json({ error: 'email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const display_name = displayName || username;
    stmtInsertUser.run({
      id,
      username,
      email,
      password: hashed,
      display_name,
      image: null,
      percentage: 0
    });

    const user = stmtGetUserById.get(id);
    res.json({ success: true, user: user });
  } catch (err) {
    console.error('signup err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- User login ----------
app.post('/api/login', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: 'usernameOrEmail and password required' });

    let user = stmtFindUserByUsername.get(usernameOrEmail);
    if (!user) user = stmtFindUserByEmail.get(usernameOrEmail);
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

// ---------- Admin login (returns JWT) ----------
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const admin = stmtFindAdminByUsername.get(username);
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

// ---------- Admin protected routes ----------
app.get('/api/admin/users', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`SELECT id, username, email, display_name, image, percentage, created_at FROM users ORDER BY created_at DESC`).all();
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// delete a completion by id or by user+lesson
app.delete('/api/admin/completion', requireAdmin, (req, res) => {
  try {
    const { id, userId, lessonId } = req.body || {};
    if (id) {
      const info = stmtDeleteCompletion.run(id);
      return res.json({ success: true, deleted: info.changes });
    }
    if (userId && lessonId) {
      const info = stmtDeleteCompletionByUserLesson.run(userId, lessonId);
      return res.json({ success: true, deleted: info.changes });
    }
    return res.status(400).json({ error: 'provide id OR (userId and lessonId)' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- Upload user image ----------
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

// ---------- Lesson complete route ----------
/**
 * Body: { userId, lessonId, totalLessons? }
 * Inserts OR IGNORE to avoid duplicates.
 * Counts completed lessons, updates users.percentage.
 */
app.post('/api/complete', (req, res) => {
  try {
    const { userId, lessonId, totalLessons } = req.body || {};
    if (!userId || !lessonId) return res.status(400).json({ error: 'userId and lessonId required' });

    const id = uuidv4();
    stmtInsertCompletion.run({ id, user_id: userId, lesson_id: lessonId });

    const stats = computeAndUpdatePercentage(userId, totalLessons ? parseInt(totalLessons) : TOTAL_LESSONS);

    res.json({ success: true, completedLessons: stats.completed, percentage: stats.percent });
  } catch (err) {
    console.error('complete err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- Debug route ----------
app.get('/api/debug', requireAdmin, (req, res) => {
  try {
    const usersCount = db.prepare(`SELECT COUNT(*) as c FROM users`).get().c;
    const adminsCount = db.prepare(`SELECT COUNT(*) as c FROM admins`).get().c;
    const completionsCount = db.prepare(`SELECT COUNT(*) as c FROM completions`).get().c;
    res.json({ ok: true, usersCount, adminsCount, completionsCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- Optional: Run code (placeholder) ----------
/**
 * This is an optional endpoint that would run code inside Docker.
 * Many hosts (including Render) do not allow Docker socket or nested Docker.
 * We'll check for docker socket and return helpful error if missing.
 *
 * POST /api/run
 * body: { language: 'python' | 'java' | 'node', code: '...' }
 */
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

    // If you have a trusted environment and Docker enabled, you would implement docker run logic here.
    return res.status(501).json({ success: false, error: 'Run-code not implemented on this deployment. Docker check passed but execution is disabled for safety.' });
  } catch (err) {
    console.error('run err', err);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- Routes to serve frontend pages (if you ship static files) ----------
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

// ---------- Safe 404 ----------
app.use((req, res) => {
  if (req.accepts('html')) {
    const f = path.join(PUBLIC_DIR, '404.html');
    if (fs.existsSync(f)) return res.status(404).sendFile(f);
    return res.status(404).send('404 - Not found');
  }
  res.status(404).json({ error: 'Not found' });
});

// ---------- Error handler ----------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: err.message || 'server error' });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT} (PID ${process.pid})`);
});
