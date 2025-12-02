// =======================
// server.js - FINAL (for Node 18+) – 1000% WORKING
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

// CONFIG
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
const BACKUPS_DIR = path.join(__dirname, "backups");
const DB_FILE = path.join(__dirname, "users.db");

// Ensure folders exist
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });

// Auto backup
function backupDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      fs.copyFileSync(DB_FILE, path.join(BACKUPS_DIR, `users_${ts}.db`));
    }
  } catch (e) {
    console.error("Backup failed:", e);
  }
}
backupDb();

// Open DB
console.log("Using DB:", DB_FILE);
const db = new sqlite3.Database(DB_FILE);

// Promises
function run(sql, params = []) {
  return new Promise((res, rej) => {
    db.run(sql, params, function (err) {
      if (err) rej(err);
      else res(this);
    });
  });
}
function get(sql, params = []) {
  return new Promise((res, rej) => {
    db.get(sql, params, (err, row) => (err ? rej(err) : res(row)));
  });
}
function all(sql, params = []) {
  return new Promise((res, rej) => {
    db.all(sql, params, (err, rows) => (err ? rej(err) : res(rows)));
  });
}

// Tables
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
      console.log("✔ Default admin created");
    }
  });
});

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

const USER_SELECT = "id, username, email, image, percentage, deleted, created_at";

// ======================== USER SIGNUP ========================
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const exists = await get(
      "SELECT id FROM users WHERE username=? OR email=?",
      [username, email]
    );
    if (exists) return res.json({ error: "User already exists" });

    const id = uuidv4();
    const img = req.file ? "/uploads/" + req.file.filename : null;

    await run(
      "INSERT INTO users (id, username, email, password, image) VALUES (?,?,?,?,?)",
      [id, username, email, bcrypt.hashSync(password, 10), img]
    );

    const user = await get(`SELECT ${USER_SELECT} FROM users WHERE id=?`, [id]);
    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.json({ error: "Server error" });
  }
});

// ======================== USER LOGIN ========================
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
    res.json({ error: "Server error" });
  }
});

// ======================== ADMIN LOGIN ========================
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await get("SELECT * FROM admins WHERE username=?", [username]);
    if (!admin) return res.json({ error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password))
      return res.json({ error: "Wrong password" });

    delete admin.password;
    res.json({ success: true, admin });
  } catch (e) {
    res.json({ error: "Server error" });
  }
});

// ======================== ADMIN USERS ========================
app.get("/api/admin/users", async (_, res) => {
  const rows = await all(`SELECT ${USER_SELECT} FROM users WHERE deleted=0 ORDER BY created_at DESC`);
  res.json({ success: true, users: rows });
});

// ======================== ADMIN OVERVIEW ========================
app.get("/api/admin/overview", async (_, res) => {
  const totalUsers = (await get("SELECT COUNT(*) AS c FROM users WHERE deleted=0")).c;
  const totalCompletions = (await get("SELECT COUNT(*) AS c FROM completions")).c;
  const avg = Math.round(
    (await get("SELECT AVG(percentage) AS a FROM users WHERE deleted=0")).a || 0
  );

  res.json({
    success: true,
    totalUsers,
    activeCourses: 1,
    totalCompletions,
    averageProgress: avg,
  });
});

// ======================== GET USER (ADMIN) ========================
app.get("/api/admin/user/:id", async (req, res) => {
  const id = req.params.id;
  const u = await get(`SELECT ${USER_SELECT} FROM users WHERE id=?`, [id]);
  if (!u) return res.json({ error: "User not found" });

  const lessons = (await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [id])).c;

  res.json({ success: true, user: u, lessonsDone: lessons });
});

// ======================== SOFT DELETE ========================
app.post("/api/admin/user/:id/soft-delete", async (req, res) => {
  await run("UPDATE users SET deleted=1 WHERE id=?", [req.params.id]);
  res.json({ success: true });
});

// ======================== RESTORE ========================
app.post("/api/admin/user/:id/restore", async (req, res) => {
  await run("UPDATE users SET deleted=0 WHERE id=?", [req.params.id]);
  res.json({ success: true });
});

// ======================== PURGE USER ========================
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

// ======================== UPDATE USER ========================
app.put("/api/admin/user/:id", async (req, res) => {
  const { username, email, password } = req.body;

  const check = await get(
    "SELECT id FROM users WHERE (username=? OR email=?) AND id<>?",
    [username, email, req.params.id]
  );
  if (check) return res.json({ error: "Username or email used" });

  if (password) {
    await run(
      "UPDATE users SET username=?, email=?, password=? WHERE id=?",
      [username, email, bcrypt.hashSync(password, 10), req.params.id]
    );
  } else {
    await run(
      "UPDATE users SET username=?, email=? WHERE id=?",
      [username, email, req.params.id]
    );
  }

  res.json({ success: true });
});

// ======================== MARK COMPLETE ========================
app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;

  await run(
    "INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?,?,?)",
    [uuidv4(), userId, String(lessonId)]
  );

  const completed = (await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [userId])).c;
  const percent = Math.round((completed / 4) * 100);

  await run("UPDATE users SET percentage=? WHERE id=?", [percent, userId]);

  backupDb();
  res.json({ success: true, percentage: percent });
});

// ======================== RUN CODE (ONLINE COMPILER) ========================
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.json({ error: "Missing data" });

    const PISTON = "https://emkc.org/api/v2/piston/execute";

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
  } catch (err) {
    res.json({ error: "RunCode failed" });
  }
});

// ======================== COURSE APIs ========================
app.post("/get-progress", async (req, res) => {
  const { username } = req.body;
  const user = await get("SELECT * FROM users WHERE username=? AND deleted=0", [username]);
  if (!user) return res.json({ success: false, error: "User not found" });

  const c = (await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [user.id])).c;

  res.json({ success: true, percentage: user.percentage, lessonsCompleted: c });
});

app.post("/save-progress", async (req, res) => {
  const { username, percentage, lessons_completed } = req.body;

  const user = await get("SELECT * FROM users WHERE username=? AND deleted=0", [username]);
  if (!user) return res.json({ success: false, error: "User not found" });

  for (let i = 1; i <= lessons_completed; i++) {
    await run(
      "INSERT OR IGNORE INTO completions VALUES (?,?,?)",
      [uuidv4(), user.id, String(i)]
    );
  }

  await run("UPDATE users SET percentage=? WHERE id=?", [percentage, user.id]);
  backupDb();

  res.json({ success: true });
});

// ======================== ROOT ========================
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// ======================== START ========================
app.listen(PORT, () => console.log(`🔥 FINAL SERVER running at http://localhost:${PORT}`));
