// =====================
//  server.js FULL WORKING PROJECT
// =====================

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");

// --------------------
// CONFIG
// --------------------
const PORT = 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");

if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// --------------------
// MULTER
// --------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) =>
    cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// --------------------
// DATABASE
// --------------------
const DB_FILE = path.join(__dirname, "users.db");
const db = new sqlite3.Database(DB_FILE);

// Promises
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

// Create tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      image TEXT,
      percentage INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS lessons (
      id TEXT PRIMARY KEY,
      course TEXT,
      title TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS completions (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      lesson_id TEXT,
      UNIQUE(user_id, lesson_id)
    )
  `);
});

// --------------------
// EXPRESS APP
// --------------------
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

// --------------------
// SIGNUP API
// --------------------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const file = req.file;

    if (!username || !email || !password)
      return res.json({ error: "Fill all fields" });

    const exists = await get(
      "SELECT 1 FROM users WHERE username=? OR email=?",
      [username, email]
    );

    if (exists) {
      if (file) fs.unlinkSync(file.path);
      return res.json({ error: "User already exists" });
    }

    const hashed = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    const imgPath = file ? "/uploads/" + file.filename : null;

    await run(
      "INSERT INTO users (id, username, email, password, image) VALUES (?, ?, ?, ?, ?)",
      [id, username, email, hashed, imgPath]
    );

    const user = await get("SELECT * FROM users WHERE id=?", [id]);
    res.json({ success: true, user });
  } catch (err) {
    console.log("Signup Error:", err);
    res.json({ error: "Server error" });
  }
});

// --------------------
// LOGIN API
// --------------------
app.post("/api/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  let user = await get("SELECT * FROM users WHERE username=?", [
    usernameOrEmail,
  ]);
  if (!user)
    user = await get("SELECT * FROM users WHERE email=?", [usernameOrEmail]);

  if (!user) return res.json({ error: "User not found" });

  const match = bcrypt.compareSync(password, user.password);
  if (!match) return res.json({ error: "Wrong password" });

  res.json({ success: true, user });
});

app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;

  const admin = await get("SELECT * FROM admins WHERE username=?", [username]);
  if (!admin) return res.json({ error: "Admin not found" });

  const ok = bcrypt.compareSync(password, admin.password);
  if (!ok) return res.json({ error: "Wrong password" });

  return res.json({ success: true, admin });
});

// --------------------
// MARK LESSON COMPLETE
// --------------------
app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;

  await run(
    "INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)",
    [uuidv4(), userId, lessonId]
  );

  const totalLessons = 4;
  const row = await get(
    "SELECT COUNT(*) AS c FROM completions WHERE user_id=?",
    [userId]
  );
  const percent = Math.round((row.c / totalLessons) * 100);

  await run("UPDATE users SET percentage=? WHERE id=?", [percent, userId]);

  res.json({ success: true, percentage: percent });
});

// --------------------
// GET MAIN PROGRESS
// --------------------
app.post("/get-main-progress", async (req, res) => {
  const { username } = req.body;
  const user = await get("SELECT * FROM users WHERE username=?", [username]);
  if (!user) return res.json({ fullStack: 0 });
  res.json({ fullStack: user.percentage });
});

// --------------------
// PAGE ROUTES
// --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// --------------------
// SERVER START
// --------------------
app.listen(PORT, () =>
  console.log(`🔥 Server running on http://localhost:${PORT}`)
);
