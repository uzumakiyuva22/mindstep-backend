// server.js  (FINAL 100% RENDER-WORKING VERSION)
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
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret";
const TOTAL_LESSONS = parseInt(process.env.TOTAL_LESSONS || "4");

// DIRECTORIES
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");

if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// MULTER — image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});
const upload = multer({ storage });

// SQLITE DATABASE
const DB_PATH = path.join(__dirname, "users.db");
const db = new sqlite3.Database(DB_PATH);

// Promisify helpers
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

// MIGRATIONS
db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON;`);

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
      UNIQUE(user_id, lesson_id)
    );
  `);
});

// DEFAULT ADMIN CREATE
(async () => {
  const admin = await get("SELECT * FROM admins WHERE username = ?", ["admin"]);
  if (!admin) {
    await run(
      "INSERT INTO admins (id, username, password, display_name) VALUES (?, ?, ?, ?)",
      [uuidv4(), "admin", bcrypt.hashSync("admin123", 10), "Administrator"]
    );
    console.log("Default admin created.");
  }
})();

// HELPERS
function removePassword(obj) {
  if (!obj) return obj;
  const { password, ...rest } = obj;
  return rest;
}

async function updatePercentage(userId) {
  const total = TOTAL_LESSONS;
  const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [userId]);
  const completed = row.c;
  const percent = Math.round((completed / total) * 100);

  await run("UPDATE users SET percentage = ? WHERE id = ?", [percent, userId]);
  return percent;
}

// EXPRESS APP
const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use('/uploads', express.static(UPLOADS_DIR));

// LOGS
app.use((req, res, next) => {
  console.log(req.method, req.url);
  next();
});

// ROUTES ------------------------------

// SIGN UP
app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ error: "Missing fields" });

    const exists = await get("SELECT 1 FROM users WHERE username = ? OR email = ?", [
      username,
      email
    ]);
    if (exists) return res.json({ error: "User already exists" });

    const hashed = bcrypt.hashSync(password, 10);
    const id = uuidv4();

    await run(
      "INSERT INTO users (id, username, email, password, display_name) VALUES (?, ?, ?, ?, ?)",
      [id, username, email, hashed, displayName || username]
    );

    const user = await get("SELECT * FROM users WHERE id = ?", [id]);
    res.json({ success: true, user: removePassword(user) });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    let user = await get("SELECT * FROM users WHERE username = ?", [usernameOrEmail]);
    if (!user)
      user = await get("SELECT * FROM users WHERE email = ?", [usernameOrEmail]);

    if (!user) return res.json({ error: "User not found" });

    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.json({ error: "Wrong password" });

    res.json({ success: true, user: removePassword(user) });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// COMPLETE LESSON
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;

    await run("INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)", [
      uuidv4(),
      userId,
      lessonId
    ]);

    const percent = await updatePercentage(userId);
    res.json({ success: true, percentage: percent });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// UPLOAD IMAGE
app.post("/api/upload-image", upload.single("image"), (req, res) => {
  const path = "/uploads/" + req.file.filename;
  res.json({ success: true, path });
});

// FRONTEND ROUTES
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});
app.get("/course.html", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "course.html"));
});
app.get("/lesson.html", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "lesson.html"));
});

// 404
app.use((req, res) => res.status(404).send("404 Not Found"));

// START SERVER
app.listen(PORT, () => console.log("Server running on port:", PORT));
