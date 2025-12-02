// =======================
// server.js - 1000% FINAL STABLE VERSION
// Soft Delete + Backups + Online Java/Python + All APIs Working
// =======================

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");

// dynamic fetch for Node (online compiler API)
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

// CONFIG
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
const BACKUPS_DIR = path.join(__dirname, "backups");
const DB_FILE = path.join(__dirname, "users.db");

// ensure folders
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });

// Auto-backup on server start
function backupDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const dest = path.join(BACKUPS_DIR, `users_${ts}.db`);
      fs.copyFileSync(DB_FILE, dest);
      console.log("✔ DB backup created:", dest);
    }
  } catch (e) {
    console.error("Backup failed:", e);
  }
}
backupDb();

// Init DB
console.log("Using DB:", DB_FILE);
const db = new sqlite3.Database(DB_FILE);

// DB Promise wrappers
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
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

// DB Tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      image TEXT,
      percentage INTEGER DEFAULT 0,
      deleted INTEGER DEFAULT 0,
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

  db.get("SELECT * FROM admins WHERE username=?", ["Uzumaki_Yuva"], async (err, row) => {
    if (!row) {
      await run(
        "INSERT INTO admins (id, username, password, display_name) VALUES (?, ?, ?, ?)",
        [uuidv4(), "Uzumaki_Yuva", bcrypt.hashSync("yuva22", 10), "MindStep Admin"]
      );
      console.log("✔ Default Admin Created (Uzumaki_Yuva / yuva22)");
    }
  });
});

// EXPRESS SETUP
const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// COMMON SELECT
const USER_SELECT = "id, username, email, image, percentage, deleted, created_at";

// -------- USER SIGNUP --------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const exists = await get("SELECT id FROM users WHERE username=? OR email=?", [username, email]);
    if (exists) return res.json({ error: "User already exists" });

    const id = uuidv4();
    const image = req.file ? "/uploads/" + req.file.filename : null;

    await run(
      "INSERT INTO users (id, username, email, password, image) VALUES (?, ?, ?, ?, ?)",
      [id, username, email, bcrypt.hashSync(password, 10), image]
    );

    const user = await get(`SELECT ${USER_SELECT} FROM users WHERE id=?`, [id]);
    res.json({ success: true, user });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// -------- USER LOGIN --------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    const user = await get(
      "SELECT * FROM users WHERE (username=? OR email=?) AND deleted=0",
      [usernameOrEmail, usernameOrEmail]
    );

    if (!user) return res.json({ error: "Invalid Login" });
    if (!bcrypt.compareSync(password, user.password))
      return res.json({ error: "Invalid Login" });

    delete user.password;
    res.json({ success: true, user });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// -------- ADMIN LOGIN --------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await get("SELECT * FROM admins WHERE username=?", [username]);

    if (!admin) return res.json({ error: "Admin not found" });
    if (!bcrypt.compareSync(password, admin.password))
      return res.json({ error: "Wrong Password" });

    delete admin.password;
    res.json({ success: true, admin });
  } catch (e) {
    res.json({ error: "Server error" });
  }
});

// -------- ADMIN USERS --------
app.get("/api/admin/users", async (req, res) => {
  const rows = await all(
    `SELECT ${USER_SELECT} FROM users WHERE deleted=0 ORDER BY created_at DESC`
  );
  res.json({ success: true, users: rows });
});

// -------- ADMIN OVERVIEW --------
app.get("/api/admin/overview", async (req, res) => {
  const totalUsers = (await get("SELECT COUNT(*) AS c FROM users WHERE deleted=0")).c;
  const completions = (await get("SELECT COUNT(*) AS c FROM completions")).c;
  const avg = Math.round(
    (await get("SELECT AVG(percentage) AS a FROM users WHERE deleted=0")).a || 0
  );

  res.json({
    success: true,
    totalUsers,
    activeCourses: 1,
    totalCompletions: completions,
    averageProgress: avg,
  });
});

// -------- ADMIN GET USER --------
app.get("/api/admin/user/:id", async (req, res) => {
  const id = req.params.id;
  const user = await get(`SELECT ${USER_SELECT} FROM users WHERE id=?`, [id]);

  if (!user) return res.json({ success: false, error: "User not found" });

  const lessons = (await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [id])).c;

  res.json({ success: true, user, lessonsDone: lessons });
});

// -------- SOFT DELETE --------
app.post("/api/admin/user/:id/soft-delete", async (req, res) => {
  await run("UPDATE users SET deleted=1 WHERE id=?", [req.params.id]);
  res.json({ success: true });
});

// -------- RESTORE USER --------
app.post("/api/admin/user/:id/restore", async (req, res) => {
  await run("UPDATE users SET deleted=0 WHERE id=?", [req.params.id]);
  res.json({ success: true });
});

// -------- PERMANENT DELETE (SAFE) --------
app.post("/api/admin/user/:id/purge", async (req, res) => {
  try {
    const id = req.params.id;
    const force = req.body.force === true || req.body.force === "true";
    if (!force)
      return res.json({ success: false, error: "Force flag required" });

    await run("DELETE FROM completions WHERE user_id=?", [id]);
    await run("DELETE FROM users WHERE id=?", [id]);

    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, error: "Server error" });
  }
});

// -------- UPDATE USER --------
app.put("/api/admin/user/:id", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const check = await get(
      "SELECT id FROM users WHERE (username=? OR email=?) AND id<>?",
      [username, email, req.params.id]
    );
    if (check) return res.json({ success: false, error: "Username or Email used" });

    if (password) {
      await run(
        "UPDATE users SET username=?, email=?, password=? WHERE id=?",
        [username, email, bcrypt.hashSync(password, 10), req.params.id]
      );
    } else {
      await run("UPDATE users SET username=?, email=? WHERE id=?", [
        username,
        email,
        req.params.id,
      ]);
    }

    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, error: "Server error" });
  }
});

// -------- MARK LESSON COMPLETE --------
app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;

  await run(
    "INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)",
    [uuidv4(), userId, String(lessonId)]
  );

  const completed = (await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [userId])).c;
  const percent = Math.round((completed / 4) * 100);

  await run("UPDATE users SET percentage=? WHERE id=?", [percent, userId]);

  backupDb();
  res.json({ success: true, percentage: percent });
});

// -------- ONLINE CODE RUNNER (JAVA, PYTHON, JS) --------
app.post("/run-code", async (req, res) => {
  const { language, source } = req.body;
  if (!language || !source) return res.json({ error: "Missing data" });

  const PISTON = "https://emkc.org/api/v2/piston/execute";

  try {
    if (language === "java") {
      const r = await fetch(PISTON, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: "java",
          version: "17.0.3",
          files: [{ name: "Main.java", content: source }],
        }),
      });
      const d = await r.json();
      return res.json({ output: d.run?.output || "No Output" });
    }

    if (language === "python") {
      const r = await fetch(PISTON, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: "python",
          version: "3.10.0",
          files: [{ name: "main.py", content: source }],
        }),
      });
      const d = await r.json();
      return res.json({ output: d.run?.output || "No Output" });
    }

    if (language === "javascript") {
      try {
        const out = eval(source);
        return res.json({ output: String(out ?? "") });
      } catch (e) {
        return res.json({ error: "JS Error: " + e.message });
      }
    }

    res.json({ error: "Language not supported" });
  } catch (e) {
    res.json({ error: "Execution failed: " + e.message });
  }
});

// -------- COURSE APIS --------
app.post("/get-progress", async (req, res) => {
  const { username } = req.body;
  const user = await get("SELECT * FROM users WHERE username=? AND deleted=0", [username]);
  if (!user) return res.json({ success: false, error: "User not found" });

  const count = (await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [user.id])).c;

  res.json({ success: true, percentage: user.percentage, lessonsCompleted: count });
});

app.post("/save-progress", async (req, res) => {
  const { username, percentage, lessons_completed } = req.body;

  const user = await get("SELECT * FROM users WHERE username=? AND deleted=0", [username]);
  if (!user) return res.json({ success: false, error: "User not found" });

  for (let i = 1; i <= lessons_completed; i++) {
    await run(
      "INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)",
      [uuidv4(), user.id, String(i)]
    );
  }

  await run("UPDATE users SET percentage=? WHERE id=?", [percentage, user.id]);
  backupDb();

  res.json({ success: true });
});

// -------- DEFAULT ROUTE --------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// -------- START SERVER --------
app.listen(PORT, () => console.log(`🔥 Server running at http://localhost:${PORT}`));
