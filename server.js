// =====================
//  server.js - FINAL CLEANED VERSION (100% WORKING)
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

// Promise wrappers
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

// --------------------
// TABLES
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

  // --------------------
  // DEFAULT ADMIN
  // --------------------
  db.get("SELECT * FROM admins WHERE username=?", ["Uzumaki_Yuva"], async (err, row) => {
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
// EXPRESS
// --------------------
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

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
    res.json({ error: "Server error" });
  }
});

// --------------------
// LOGIN
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
  } catch {
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

  const ok = bcrypt.compareSync(password, admin.password);
  if (!ok) return res.json({ error: "Wrong password" });

  return res.json({ success: true, admin });
});

// --------------------
// ADMIN: USERS LIST
// --------------------
app.get("/api/admin/users", async (req, res) => {
  const rows = await all(
    "SELECT id, username, email, image, percentage, created_at FROM users ORDER BY created_at DESC"
  );
  res.json({ success: true, users: rows });
});

// --------------------
// ADMIN: GET USER DETAILS
// --------------------
app.get("/api/admin/user/:id", async (req, res) => {
  const id = req.params.id;
  const user = await get(
    "SELECT id, username, email, image, percentage, created_at FROM users WHERE id=?",
    [id]
  );
  if (!user) return res.json({ success: false, error: "User not found" });

  const row = await get(
    "SELECT COUNT(*) AS c FROM completions WHERE user_id=?",
    [id]
  );

  res.json({ success: true, user, lessonsDone: row.c });
});

// --------------------
// ADMIN: UPDATE USER
// --------------------
app.put("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const { username, email, password } = req.body;

    if (!username || !email)
      return res.json({ success: false, error: "Missing fields" });

    const exists = await get(
      "SELECT id FROM users WHERE (username=? OR email=?) AND id<>?",
      [username, email, id]
    );
    if (exists) return res.json({ success: false, error: "Already used" });

    if (password) {
      const hashed = bcrypt.hashSync(password, 10);
      await run(
        "UPDATE users SET username=?, email=?, password=? WHERE id=?",
        [username, email, hashed, id]
      );
    } else {
      await run(
        "UPDATE users SET username=?, email=? WHERE id=?",
        [username, email, id]
      );
    }
    res.json({ success: true });
  } catch {
    res.json({ success: false });
  }
});

// --------------------
// ADMIN: UPLOAD USER IMAGE
// --------------------
app.post("/api/admin/user/:id/image", upload.single("image"), async (req, res) => {
  if (!req.file) return res.json({ success: false });

  const id = req.params.id;
  const imagePath = "/uploads/" + req.file.filename;

  await run("UPDATE users SET image=? WHERE id=?", [imagePath, id]);
  res.json({ success: true, image: imagePath });
});

// --------------------
// ADMIN: DELETE USER
// --------------------
app.delete("/api/admin/user/:id", async (req, res) => {
  const id = req.params.id;

  await run("DELETE FROM completions WHERE user_id=?", [id]);
  await run("DELETE FROM users WHERE id=?", [id]);

  res.json({ success: true });
});

// --------------------
// ADMIN: RESET PROGRESS
// --------------------
app.post("/api/admin/user/:id/reset", async (req, res) => {
  const id = req.params.id;

  await run("DELETE FROM completions WHERE user_id=?", [id]);
  await run("UPDATE users SET percentage=0 WHERE id=?", [id]);

  res.json({ success: true });
});

// --------------------
// ADMIN: LESSON COUNT
// --------------------
app.get("/api/admin/user/:id/lessons", async (req, res) => {
  const id = req.params.id;
  const row = await get(
    "SELECT COUNT(*) AS c FROM completions WHERE user_id=?",
    [id]
  );
  res.json({ success: true, count: row.c });
});

// --------------------
// COURSE CRUD
// --------------------
app.post("/api/admin/course", async (req, res) => {
  const { title, desc } = req.body;
  if (!title) return res.json({ success: false });

  const id = uuidv4();
  await run("INSERT INTO courses (id, title, description) VALUES (?,?,?)", [
    id,
    title,
    desc || "",
  ]);

  res.json({ success: true });
});

app.get("/api/admin/courses", async (req, res) => {
  const rows = await all(
    "SELECT id, title, description, created_at FROM courses ORDER BY created_at DESC"
  );
  res.json({ success: true, courses: rows });
});

app.delete("/api/admin/course/:id", async (req, res) => {
  await run("DELETE FROM courses WHERE id=?", [req.params.id]);
  res.json({ success: true });
});

// --------------------
// RUN CODE (JAVA / PYTHON / JS)
// --------------------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;

    if (!language || !source)
      return res.json({ error: "Missing inputs" });

    if (language === "java") {
      fs.writeFileSync("Main.java", source);
      exec("javac Main.java", (err) => {
        if (err) return res.json({ error: err.message });

        exec("java Main", (err2, output) => {
          if (err2) return res.json({ error: err2.message });
          res.json({ output });
        });
      });
      return;
    }

    if (language === "python") {
      fs.writeFileSync("script.py", source);
      exec("python script.py", (err, output) => {
        if (err) return res.json({ error: err.message });
        res.json({ output });
      });
      return;
    }

    if (language === "javascript") {
      try {
        const result = eval(source);
        res.json({ output: String(result) });
      } catch (error) {
        res.json({ error: error.message });
      }
      return;
    }

    res.json({ error: "Unsupported language" });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// --------------------
// MAIN PROGRESS
// --------------------
app.post("/get-main-progress", async (req, res) => {
  const user = await get("SELECT percentage FROM users WHERE username=?", [
    req.body.username,
  ]);
  res.json({ fullStack: user?.percentage || 0 });
});

// --------------------
// PAGE ROUTES
// --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// --------------------
// START SERVER
// --------------------
app.listen(PORT, () =>
  console.log(`🔥 Server running on http://localhost:${PORT}`)
);
