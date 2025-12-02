// =====================
//  server.js FULL WORKING PROJECT (FIXED VERSION)
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

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
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
    CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT,
  display_name TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

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

  // DEFAULT ADMIN
  // DEFAULT ADMIN (CUSTOM)
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
    console.log("✔ Custom admin created (Uzumaki_Yuva / yuva22)");
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
// SIGNUP API (FIXED display_name issue)
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
// LOGIN API
// --------------------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    let user = await get("SELECT * FROM users WHERE username=? OR email=?", [
      usernameOrEmail,
      usernameOrEmail
    ]);

    if (!user) return res.json({ error: "Invalid Login" });

    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.json({ error: "Invalid Login" });

    res.json({ success: true, user });

  } catch (err) {
    res.json({ error: "Server error" });
  }
});

// --------------------
// ADMIN LOGIN API (fixed table)
// --------------------
app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;

  const admin = await get("SELECT * FROM admins WHERE username=?", [username]);
  if (!admin) return res.json({ error: "Admin not found" });

  const ok = bcrypt.compareSync(password, admin.password);
  if (!ok) return res.json({ error: "Wrong password" });

  return res.json({ success: true, admin });
});

// --------------------
// ADMIN USERS
// --------------------
app.get("/api/admin/users", async (req, res) => {
  try {
    const rows = await all(
      "SELECT id, username, email, image, percentage, created_at FROM users ORDER BY created_at DESC"
    );
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error(err);
    res.json({ success: false });
  }
});

// --------------------
// ADMIN TOTAL USERS
// --------------------
app.get("/api/admin/total-users", async (req, res) => {
  try {
    const row = await get("SELECT COUNT(*) AS total FROM users");
    res.json({ success: true, total: row.total });
  } catch (err) {
    console.error(err);
    res.json({ success: false });
  }
});

// --------------------
// ADMIN OVERVIEW
// --------------------
app.get("/api/admin/overview", async (req, res) => {
  try {
    const users = await get("SELECT COUNT(*) AS total FROM users");

    res.json({
      success: true,
      totalUsers: users.total,
      activeCourses: 5,
      dailyVisits: 224,
      reports: 3
    });

  } catch (err) {
    res.json({ success: false });
  }
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
// ADMIN: get single user + lessons count
// --------------------
app.get("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const user = await get("SELECT id, username, email, image, percentage, created_at FROM users WHERE id = ?", [id]);
    if (!user) return res.json({ success: false, error: "User not found" });

    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [id]);
    const lessonsDone = row ? row.c : 0;
    res.json({ success: true, user, lessonsDone });
  } catch (err) {
    console.error(err); res.json({ success: false });
  }
});

// --------------------
// ADMIN: update user (name/email/password)
// --------------------
app.put("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const { username, email, password } = req.body;
    // basic validation
    if(!username || !email) return res.json({ success:false, error: "Missing fields" });

    // check for collisions (other users)
    const other = await get("SELECT id FROM users WHERE (username=? OR email=?) AND id<>?", [username, email, id]);
    if(other) return res.json({ success:false, error: "Username or email already used" });

    if(password && password.length > 0) {
      const hashed = bcrypt.hashSync(password, 10);
      await run("UPDATE users SET username=?, email=?, password=? WHERE id=?", [username, email, hashed, id]);
    } else {
      await run("UPDATE users SET username=?, email=? WHERE id=?", [username, email, id]);
    }
    res.json({ success:true });
  } catch(err){ console.error(err); res.json({ success:false }); }
});

// --------------------
// ADMIN: upload user image
// --------------------
app.post("/api/admin/user/:id/image", upload.single("image"), async (req, res) => {
  try {
    const id = req.params.id;
    if(!req.file) return res.json({ success:false, error: "No file" });
    const imagePath = "/uploads/" + req.file.filename;
    await run("UPDATE users SET image=? WHERE id=?", [imagePath, id]);
    res.json({ success:true, image: imagePath });
  } catch(err){ console.error(err); res.json({ success:false }); }
});

// --------------------
// ADMIN: delete user
// --------------------
app.delete("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    // remove completions first (foreign-like cleanup)
    await run("DELETE FROM completions WHERE user_id = ?", [id]);
    await run("DELETE FROM users WHERE id = ?", [id]);
    res.json({ success: true });
  } catch(err){ console.error(err); res.json({ success:false }); }
});

// --------------------
// ADMIN: reset user progress
// --------------------
app.post("/api/admin/user/:id/reset", async (req, res) => {
  try {
    const id = req.params.id;
    await run("DELETE FROM completions WHERE user_id = ?", [id]);
    await run("UPDATE users SET percentage = 0 WHERE id = ?", [id]);
    res.json({ success:true });
  } catch(err){ console.error(err); res.json({ success:false }); }
});

// --------------------
// ADMIN: lessons count for a user (used to fill table)
// --------------------
app.get("/api/admin/user/:id/lessons", async (req, res) => {
  try {
    const id = req.params.id;
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [id]);
    res.json({ success:true, count: row ? row.c : 0 });
  } catch(err){ console.error(err); res.json({ success:false }); }
});

// --------------------
// COURSES CRUD (simple table-based)
// --------------------
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS courses (
    id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
});

app.post("/api/admin/course", async (req, res) => {
  try {
    const { title, desc } = req.body;
    if(!title) return res.json({ success:false, error:"Title required" });
    const id = uuidv4();
    await run("INSERT INTO courses (id, title, description) VALUES (?,?,?)", [id, title, desc||'']);
    res.json({ success:true, id });
  } catch(err){ console.error(err); res.json({ success:false }); }
});

app.get("/api/admin/courses", async (req, res) => {
  try {
    const rows = await all("SELECT id, title, description, created_at FROM courses ORDER BY created_at DESC");
    res.json({ success:true, courses: rows });
  } catch(err){ console.error(err); res.json({ success:false }); }
});

app.delete("/api/admin/course/:id", async (req, res) => {
  try {
    const id = req.params.id;
    await run("DELETE FROM courses WHERE id = ?", [id]);
    res.json({ success:true });
  } catch(err){ console.error(err); res.json({ success:false }); }
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
