// =======================
// FINAL SERVER.JS (ONLINE JAVA & PYTHON)
// Works on Mobile, Laptop, Desktop, Without JDK
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

// ---- ADD FETCH FOR ONLINE API ----
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

// --------------------
// CONFIG
// --------------------
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");

// ensure folders exist
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// --------------------
// DATABASE (permanent file)
// --------------------
const DB_FILE = path.join(__dirname, "users.db");
console.log("Using DB:", DB_FILE);
const db = new sqlite3.Database(DB_FILE);

// sqlite helpers
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

// --------------------
// DB setup
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

  // Default admin
  db.get("SELECT * FROM admins WHERE username=?", ["Uzumaki_Yuva"], async (err, row) => {
    if (!row) {
      await run(
        "INSERT INTO admins (id, username, password, display_name) VALUES (?, ?, ?, ?)",
        [uuidv4(), "Uzumaki_Yuva", bcrypt.hashSync("yuva22", 10), "MindStep Admin"]
      );
      console.log("✔ Default admin created: Uzumaki_Yuva / yuva22");
    }
  });
});

// --------------------
// EXPRESS
// --------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

// --------------------
// MULTER
// --------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// --------------------
// SIGNUP
// --------------------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const exists = await get(
      "SELECT id FROM users WHERE username=? OR email=?",
      [username, email]
    );
    if (exists) return res.json({ error: "User already exists" });

    const id = uuidv4();
    const image = req.file ? "/uploads/" + req.file.filename : null;

    await run(
      "INSERT INTO users (id, username, email, password, image) VALUES (?, ?, ?, ?, ?)",
      [id, username, email, bcrypt.hashSync(password, 10), image]
    );

    const user = await get(
      "SELECT id, username, email, image, percentage FROM users WHERE id=?",
      [id]
    );

    res.json({ success: true, user });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// LOGIN USER
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

    delete user.password;
    res.json({ success: true, user });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// LOGIN ADMIN
// --------------------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const admin = await get("SELECT * FROM admins WHERE username=?", [username]);
    if (!admin) return res.json({ error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password))
      return res.json({ error: "Wrong password" });

    delete admin.password;
    res.json({ success: true, admin });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// ADMIN API
// --------------------
app.get("/api/admin/users", async (req, res) => {
  const rows = await all(
    "SELECT id, username, email, image, percentage, created_at FROM users ORDER BY created_at DESC"
  );
  res.json({ success: true, users: rows });
});

app.get("/api/admin/overview", async (req, res) => {
  const totalUsers = (await get("SELECT COUNT(*) AS c FROM users")).c;
  const totalCompletions = (await get("SELECT COUNT(*) AS c FROM completions")).c;
  const avgPercent = Math.round(
    (await get("SELECT AVG(percentage) AS avgp FROM users")).avgp || 0
  );

  res.json({
    success: true,
    totalUsers,
    activeCourses: 1,
    totalCompletions,
    averageProgress: avgPercent,
  });
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

  const completed = (
    await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [userId])
  ).c;

  const percent = Math.round((completed / 4) * 100);

  await run("UPDATE users SET percentage=? WHERE id=?", [percent, userId]);

  res.json({ success: true, percentage: percent });
});

// --------------------
// ONLINE RUN-CODE (JAVA / PYTHON / JS)
// --------------------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;

    // ---- JAVA ONLINE ----
    if (language === "java") {
      const response = await fetch("https://emkc.org/api/v2/piston/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: "java",
          version: "17.0.3",
          files: [{ name: "Main.java", content: source }],
        }),
      });

      const data = await response.json();
      return res.json({ output: data.run?.output || "No Output" });
    }

    // ---- PYTHON ONLINE ----
    if (language === "python") {
      const response = await fetch("https://emkc.org/api/v2/piston/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: "python",
          version: "3.10.0",
          files: [{ name: "main.py", content: source }],
        }),
      });

      const data = await response.json();
      return res.json({ output: data.run?.output || "No Output" });
    }

    // ---- JAVASCRIPT LOCAL ----
    if (language === "javascript") {
      try {
        const result = eval(source);
        return res.json({ output: String(result ?? "") });
      } catch (err) {
        return res.json({ error: "JS Error: " + err.message });
      }
    }

    res.json({ error: "Language not supported" });
  } catch (err) {
    res.json({ error: "RunCode Error: " + err.message });
  }
});

// --------------------
// COURSE API (your original)
// --------------------
app.post("/get-progress", async (req, res) => {
  const { username } = req.body;
  const user = await get("SELECT * FROM users WHERE username=?", [username]);
  const count = (
    await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [user.id])
  ).c;

  res.json({ success: true, percentage: user.percentage, lessonsCompleted: count });
});

app.post("/save-progress", async (req, res) => {
  const { username, percentage, lessons_completed } = req.body;

  const user = await get("SELECT * FROM users WHERE username=?", [username]);

  await run("UPDATE users SET percentage=? WHERE id=?", [percentage, user.id]);

  for (let i = 1; i <= lessons_completed; i++) {
    await run(
      "INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)",
      [uuidv4(), user.id, i]
    );
  }

  res.json({ success: true });
});

// --------------------
// DEFAULT ROUTE
// --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// --------------------
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));
