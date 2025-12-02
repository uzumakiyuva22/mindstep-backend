// =====================
//  FINAL PRODUCTION SERVER.JS (100% WORKING)
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
const { exec } = require("child_process");

// --------------------
// CONFIG
// --------------------
const PORT = 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");

// Ensure folders exist
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// --------------------
// DATABASE (Permanent)
// --------------------
const DB_FILE = path.join(__dirname, "users.db");
console.log("📌 Using Database:", DB_FILE);

const db = new sqlite3.Database(DB_FILE);

// PROMISE HELPERS
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

// --------------------
// DATABASE SETUP
// --------------------
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
    CREATE TABLE IF NOT EXISTS admins (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      display_name TEXT,
      created_at TEXT DEFAULT (datetime('now'))
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

  db.run(`
    CREATE TABLE IF NOT EXISTS courses (
      id TEXT PRIMARY KEY,
      title TEXT,
      description TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // CREATE DEFAULT ADMIN IF NOT EXISTS
  db.get("SELECT * FROM admins WHERE username = ?", ["Uzumaki_Yuva"], async (err, row) => {
    if (!row) {
      await run(
        "INSERT INTO admins (id, username, password, display_name) VALUES (?, ?, ?, ?)",
        [
          uuidv4(),
          "Uzumaki_Yuva",
          bcrypt.hashSync("yuva22", 10),
          "MindStep Administrator"
        ]
      );
      console.log("✔ Default admin created: Uzumaki_Yuva / yuva22");
    }
  });
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
// FILE UPLOAD (PROFILE PIC)
// --------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) =>
    cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// --------------------
// SIGNUP
// --------------------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.json({ error: "Missing fields" });

    const exists = await get(
      "SELECT 1 FROM users WHERE username=? OR email=?",
      [username, email]
    );
    if (exists) return res.json({ error: "User already exists" });

    const hashed = bcrypt.hashSync(password, 10);
    const id = uuidv4();

    const imagePath = req.file ? "/uploads/" + req.file.filename : null;

    await run(
      "INSERT INTO users (id, username, email, password, image) VALUES (?, ?, ?, ?, ?)",
      [id, username, email, hashed, imagePath]
    );

    const user = await get("SELECT * FROM users WHERE id=?", [id]);
    res.json({ success: true, user });

  } catch (err) {
    console.log("Signup error:", err);
    res.json({ error: "Server error" });
  }
});

// --------------------
// LOGIN
// --------------------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    const user = await get(
      "SELECT * FROM users WHERE username=? OR email=?",
      [usernameOrEmail, usernameOrEmail]
    );

    if (!user) return res.json({ error: "Invalid Login" });
    if (!bcrypt.compareSync(password, user.password))
      return res.json({ error: "Invalid Login" });

    res.json({ success: true, user });

  } catch (err) {
    res.json({ error: "Server error" });
  }
});

// --------------------
// ADMIN LOGIN
// --------------------
app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;

  const admin = await get("SELECT * FROM admins WHERE username=?", [username]);
  if (!admin) return res.json({ error: "Admin not found" });

  if (!bcrypt.compareSync(password, admin.password))
    return res.json({ error: "Wrong password" });

  return res.json({ success: true, admin });
});

// --------------------
// GET USERS (ADMIN)
// --------------------
app.get("/api/admin/users", async (req, res) => {
  try {
    const rows = await all(
      "SELECT id, username, email, image, percentage, created_at FROM users ORDER BY created_at DESC"
    );
    res.json({ success: true, users: rows });
  } catch (err) {
    res.json({ success: false });
  }
});

// --------------------
// ADMIN DELETE USER
// --------------------
app.delete("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    await run("DELETE FROM completions WHERE user_id = ?", [id]);
    await run("DELETE FROM users WHERE id = ?", [id]);
    res.json({ success: true });
  } catch {
    res.json({ success: false });
  }
});

// --------------------
// RUN CODE (Java / Python / JS)
// --------------------
app.post("/run-code", (req, res) => {
  const { language, source } = req.body;

  if (!language || !source)
    return res.json({ error: "Missing fields" });

  // ---------------- JAVA ----------------
  if (language === "java") {
    fs.writeFileSync("Main.java", source);

    exec("javac Main.java", (err) => {
      if (err) return res.json({ error: err.message });

      exec("java Main", (err, output) =>
        err ? res.json({ error: err.message }) : res.json({ output })
      );
    });
    return;
  }

  // ---------------- PYTHON ----------------
  if (language === "python") {
    fs.writeFileSync("script.py", source);

    exec("python script.py", (err, output) =>
      err ? res.json({ error: err.message }) : res.json({ output })
    );
    return;
  }

  // ---------------- JAVASCRIPT ----------------
  if (language === "javascript") {
    try {
      let result = eval(source);
      res.json({ output: String(result ?? "") });
    } catch (err) {
      res.json({ error: err.message });
    }
    return;
  }

  res.json({ error: "Language not supported" });
});

// --------------------
// DEFAULT PAGE
// --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// --------------------
// START SERVER
// --------------------
app.listen(PORT, () =>
  console.log(`🔥 MindStep Server running → http://localhost:${PORT}`)
);
