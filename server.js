// server.js - FINAL (soft-delete, backups, online Java/Python via Piston, all APIs)
// Requirements: node >= 18 (or earlier with node-fetch polyfill). Run: npm install express cors multer bcryptjs sqlite3 uuid node-fetch

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");

// dynamic fetch for Node
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

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

// helper: backup DB on startup (timestamped)
function backupDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const dest = path.join(BACKUPS_DIR, `users_${ts}.db`);
      fs.copyFileSync(DB_FILE, dest);
      console.log("✔ DB backup created:", dest);
    } else {
      console.log("No existing DB to backup (fresh start).");
    }
  } catch (e) {
    console.error("DB backup failed:", e);
  }
}

// create backup on start
backupDb();

// open/create sqlite db
console.log("Using DB:", DB_FILE);
const db = new sqlite3.Database(DB_FILE);

// sqlite promise wrappers
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
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

// DB setup (soft-delete column)
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

  db.run(`
    CREATE TABLE IF NOT EXISTS courses (
      id TEXT PRIMARY KEY,
      title TEXT,
      description TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // default admin (if missing)
  db.get("SELECT * FROM admins WHERE username = ?", ["Uzumaki_Yuva"], async (err, row) => {
    if (err) {
      console.error("Admin lookup error:", err);
      return;
    }
    if (!row) {
      try {
        await run(
          "INSERT INTO admins (id, username, password, display_name) VALUES (?, ?, ?, ?)",
          [uuidv4(), "Uzumaki_Yuva", bcrypt.hashSync("yuva22", 10), "MindStep Administrator"]
        );
        console.log("✔ Default admin created: Uzumaki_Yuva / yuva22");
      } catch (e) {
        console.error("Failed to create default admin:", e);
      }
    }
  });
});

// EXPRESS
const app = express();
app.use(cors());
app.use(express.json({ limit: "6mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

// multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ---------- HELPERS ----------
function safeUnlink(filePath) {
  try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) {}
}

// Filter users by deleted flag for queries
const USER_SELECT_BASE = "id, username, email, image, percentage, deleted, created_at";

// ---------- AUTH APIs ----------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

    const existing = await get("SELECT id FROM users WHERE (username=? OR email=?)", [username, email]);
    if (existing) return res.json({ error: "User already exists" });

    const id = uuidv4();
    const image = req.file ? "/uploads/" + req.file.filename : null;
    await run("INSERT INTO users (id, username, email, password, image) VALUES (?, ?, ?, ?, ?)", [
      id,
      username,
      email,
      bcrypt.hashSync(password, 10),
      image,
    ]);

    const user = await get(`SELECT ${USER_SELECT_BASE} FROM users WHERE id=?`, [id]);
    res.json({ success: true, user });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Missing fields" });

    const user = await get("SELECT * FROM users WHERE (username=? OR email=?) AND (deleted IS NULL OR deleted=0)", [usernameOrEmail, usernameOrEmail]);
    if (!user) return res.json({ error: "Invalid Login" });

    if (!bcrypt.compareSync(password, user.password)) return res.json({ error: "Invalid Login" });

    // remove password before sending
    delete user.password;
    res.json({ success: true, user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin login
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    const admin = await get("SELECT * FROM admins WHERE username=?", [username]);
    if (!admin) return res.json({ error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password)) return res.json({ error: "Wrong password" });

    delete admin.password;
    res.json({ success: true, admin });
  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN APIs (soft-delete policy) ----------
app.get("/api/admin/users", async (req, res) => {
  try {
    const rows = await all(`SELECT ${USER_SELECT_BASE} FROM users WHERE deleted IS NULL OR deleted=0 ORDER BY created_at DESC`);
    res.json({ success: true, users: rows });
  } catch (e) {
    console.error("Fetch users error:", e);
    res.status(500).json({ success: false });
  }
});

// admin overview
app.get("/api/admin/overview", async (req, res) => {
  try {
    const totalUsersRow = await get("SELECT COUNT(*) AS c FROM users WHERE deleted IS NULL OR deleted=0");
    const totalCompletionsRow = await get("SELECT COUNT(*) AS c FROM completions");
    const avgPercentRow = await get("SELECT AVG(percentage) AS avgp FROM users WHERE deleted IS NULL OR deleted=0");

    res.json({
      success: true,
      totalUsers: totalUsersRow ? totalUsersRow.c : 0,
      activeCourses: 1,
      totalCompletions: totalCompletionsRow ? totalCompletionsRow.c : 0,
      averageProgress: Math.round(avgPercentRow?.avgp || 0)
    });
  } catch (e) {
    console.error("admin overview error:", e);
    res.status(500).json({ success: false });
  }
});

// get single user (admin)
app.get("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const user = await get(`SELECT ${USER_SELECT_BASE} FROM users WHERE id = ?`, [id]);
    if (!user) return res.json({ success: false, error: "User not found" });

    const lessonsRow = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [id]);
    res.json({ success: true, user, lessonsDone: lessonsRow ? lessonsRow.c : 0 });
  } catch (e) {
    console.error("admin get user error:", e);
    res.status(500).json({ success: false });
  }
});

// soft-delete user (mark deleted=1) — safe, reversible
app.post("/api/admin/user/:id/soft-delete", async (req, res) => {
  try {
    const id = req.params.id;
    await run("UPDATE users SET deleted=1 WHERE id=?", [id]);
    // optional: keep completions for recovery; we do not delete completions to retain history
    return res.json({ success: true });
  } catch (e) {
    console.error("admin soft-delete error:", e);
    res.status(500).json({ success: false });
  }
});

// undelete (restore) user
app.post("/api/admin/user/:id/restore", async (req, res) => {
  try {
    const id = req.params.id;
    await run("UPDATE users SET deleted=0 WHERE id=?", [id]);
    return res.json({ success: true });
  } catch (e) {
    console.error("admin restore error:", e);
    res.status(500).json({ success: false });
  }
});

// permanently purge user (only with explicit force=true)
app.post("/api/admin/user/:id/purge", async (req, res) => {
  try {
    const id = req.params.id;
    const force = req.body.force === true || req.body.force === "true";
    if (!force) return res.json({ success: false, error: "Force flag required" });

    // remove completions then user
    await run("DELETE FROM completions WHERE user_id = ?", [id]);
    await run("DELETE FROM users WHERE id = ?", [id]);
    return res.json({ success: true });
  } catch (e) {
    console.error("admin purge error:", e);
    res.status(500).json({ success: false });
  }
}

// update user (admin)
app.put("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const { username, email, password } = req.body;
    if (!username || !email) return res.json({ success: false, error: "Missing fields" });

    const other = await get("SELECT id FROM users WHERE (username=? OR email=?) AND id<>?", [username, email, id]);
    if (other) return res.json({ success: false, error: "Username or email used" });

    if (password && password.length > 0) {
      const hashed = bcrypt.hashSync(password, 10);
      await run("UPDATE users SET username=?, email=?, password=? WHERE id=?", [username, email, hashed, id]);
    } else {
      await run("UPDATE users SET username=?, email=? WHERE id=?", [username, email, id]);
    }
    return res.json({ success: true });
  } catch (e) {
    console.error("Update user error:", e);
    res.status(500).json({ success: false });
  }
}

// upload image
app.post("/api/admin/user/:id/image", upload.single("image"), async (req, res) => {
  try {
    const id = req.params.id;
    if (!req.file) return res.json({ success: false, error: "No file uploaded" });
    const imagePath = "/uploads/" + req.file.filename;
    await run("UPDATE users SET image=? WHERE id=?", [imagePath, id]);
    return res.json({ success: true, image: imagePath });
  } catch (e) {
    console.error("Upload image error:", e);
    res.status(500).json({ success: false });
  }
});

app.get("/api/admin/user/:id/lessons", async (req, res) => {
  try {
    const id = req.params.id;
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [id]);
    return res.json({ success: true, count: row ? row.c : 0 });
  } catch (e) {
    console.error("User lessons error:", e);
    res.status(500).json({ success: false });
  }
});

// ---------- COMPLETIONS / COURSE ----------
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ error: "Missing fields" });

    await run("INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)", [uuidv4(), userId, String(lessonId)]);

    const totalLessons = 4; // change if you add more lessons
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [userId]);
    const percent = Math.round(((row && row.c) || 0) / totalLessons * 100);
    await run("UPDATE users SET percentage=? WHERE id=?", [percent, userId]);

    // create backup after progress update for safety
    backupDb();

    return res.json({ success: true, percentage: percent });
  } catch (e) {
    console.error("Complete error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- RUN CODE: Using Piston (online) for Java & Python ----------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    // Piston endpoint
    const PISTON = "https://emkc.org/api/v2/piston/execute";

    if (language === "java") {
      try {
        const response = await fetch(PISTON, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            language: "java",
            version: "17.0.3",
            files: [{ name: "Main.java", content: source }]
          })
        });
        const data = await response.json();
        const out = (data && data.run && data.run.output) ? data.run.output : JSON.stringify(data);
        return res.json({ output: out });
      } catch (err) {
        console.error("Online Java error:", err);
        return res.json({ error: "Online Java API error: " + err.message });
      }
    }

    if (language === "python") {
      try {
        const response = await fetch(PISTON, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            language: "python",
            version: "3.10.0",
            files: [{ name: "main.py", content: source }]
          })
        });
        const data = await response.json();
        const out = (data && data.run && data.run.output) ? data.run.output : JSON.stringify(data);
        return res.json({ output: out });
      } catch (err) {
        console.error("Online Python error:", err);
        return res.json({ error: "Online Python API error: " + err.message });
      }
    }

    if (language === "javascript") {
      try {
        const result = eval(source);
        return res.json({ output: String(result ?? "") });
      } catch (err) {
        return res.json({ error: "JS Error: " + err.message });
      }
    }

    return res.json({ error: "Language not supported" });
  } catch (e) {
    console.error("run-code handler error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- Course endpoints used by course.html ----------
app.post("/get-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await get("SELECT id, percentage FROM users WHERE username=? AND (deleted IS NULL OR deleted=0)", [username]);
    if (!user) return res.json({ success:false, error: "User not found" });
    const comp = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [user.id]);
    const lessonsCompleted = comp ? comp.c : 0;
    res.json({ success:true, percentage: user.percentage || 0, lessonsCompleted });
  } catch (e) {
    console.error("get-progress error:", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

app.post("/save-progress", async (req, res) => {
  try {
    const { username, percentage, lessons_completed } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await get("SELECT id FROM users WHERE username=? AND (deleted IS NULL OR deleted=0)", [username]);
    if (!user) return res.json({ success:false, error: "User not found" });
    const uid = user.id;
    const n = Math.max(0, Number(lessons_completed || 0));
    for (let i=1;i<=n;i++){
      await run("INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?,?,?)", [uuidv4(), uid, String(i)]);
    }
    const pct = Math.max(0, Math.min(100, Number(percentage || 0)));
    await run("UPDATE users SET percentage=? WHERE id=?", [pct, uid]);
    backupDb();
    return res.json({ success:true, percentage: pct, lessons_completed: n });
  } catch (e) {
    console.error("save-progress error:", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

app.post("/update-main-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await get("SELECT id FROM users WHERE username=? AND (deleted IS NULL OR deleted=0)", [username]);
    if (!user) return res.json({ success:false, error: "User not found" });
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [user.id]);
    const totalLessons = 4;
    const percent = Math.round(((row && row.c) || 0) / totalLessons * 100);
    await run("UPDATE users SET percentage=? WHERE id=?", [percent, user.id]);
    backupDb();
    return res.json({ success:true, percentage: percent });
  } catch (e) {
    console.error("update-main-progress error:", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

app.post("/get-main-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await get("SELECT percentage FROM users WHERE username = ? AND (deleted IS NULL OR deleted=0)", [username]);
    return res.json({ success: true, fullStack: (user ? user.percentage : 0) || 0 });
  } catch (e) {
    console.error("get-main-progress error:", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

app.get("/progress", async (req, res) => {
  try {
    const usersRow = await get("SELECT COUNT(*) AS c FROM users WHERE deleted IS NULL OR deleted=0");
    const usersCount = usersRow ? usersRow.c : 0;
    const completionsRow = await get("SELECT COUNT(*) AS c FROM completions");
    const totalCompletions = completionsRow ? completionsRow.c : 0;
    const avgPercentRow = await get("SELECT AVG(percentage) AS avgp FROM users WHERE deleted IS NULL OR deleted=0");
    const avgPct = avgPercentRow ? Math.round(avgPercentRow.avgp || 0) : 0;
    res.json({ percentage: avgPct, completed: totalCompletions, users: usersCount });
  } catch (e) {
    console.error("progress summary error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// default
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// ensure POST endpoints return JSON (catch-all)
app.use((req, res, next) => {
  if (req.method === "POST") return res.status(404).json({ error: "Endpoint not found" });
  next();
});

// start
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));
