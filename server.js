// server.js (cleaned + hardened version)
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
const util = require("util");
const execP = util.promisify(exec);

// --------------------
// CONFIG
// --------------------
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");

// ensure folders
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// --------------------
// DATABASE (permanent file)
// --------------------
const DB_FILE = path.join(__dirname, "users.db");
console.log("Using DB:", DB_FILE);

const db = new sqlite3.Database(DB_FILE);

// Promise wrappers for sqlite
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

// --------------------
// DB setup & default admin
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

  // Insert default admin if missing
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

// --------------------
// EXPRESS App
// --------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

// --------------------
// Multer for profile uploads
// --------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// --------------------
// Helpers
// --------------------
async function commandAvailable(cmd) {
  try {
    // '-version' usually prints to stderr for javac/java
    await execP(`${cmd} -version`);
    return true;
  } catch (e) {
    return false;
  }
}

// --------------------
// SIGN UP
// --------------------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.json({ error: "Missing fields" });

    const exists = await get("SELECT 1 FROM users WHERE username=? OR email=?", [username, email]);
    if (exists) return res.json({ error: "User already exists" });

    const hashed = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    const imagePath = req.file ? "/uploads/" + req.file.filename : null;

    await run("INSERT INTO users (id, username, email, password, image) VALUES (?, ?, ?, ?, ?)", [
      id,
      username,
      email,
      hashed,
      imagePath,
    ]);

    const user = await get("SELECT id, username, email, image, percentage, created_at FROM users WHERE id=?", [id]);
    res.json({ success: true, user });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// LOGIN (user)
// --------------------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.json({ error: "Missing fields" });

    const user = await get("SELECT * FROM users WHERE username=? OR email=?", [usernameOrEmail, usernameOrEmail]);
    if (!user) return res.json({ error: "Invalid Login" });

    if (!bcrypt.compareSync(password, user.password)) return res.json({ error: "Invalid Login" });

    // return without password
    delete user.password;
    res.json({ success: true, user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// ADMIN LOGIN
// --------------------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ error: "Missing fields" });

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

// --------------------
// Admin: list users
// --------------------
app.get("/api/admin/users", async (req, res) => {
  try {
    const rows = await all("SELECT id, username, email, image, percentage, created_at FROM users ORDER BY created_at DESC");
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error("Fetch users error:", err);
    res.status(500).json({ success: false });
  }
});

// --------------------
// Admin: delete user
// --------------------
app.delete("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    await run("DELETE FROM completions WHERE user_id = ?", [id]);
    await run("DELETE FROM users WHERE id = ?", [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ success: false });
  }
});

// --------------------
// Admin: update user (name/email/password)
// --------------------
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
    res.json({ success: true });
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ success: false });
  }
});

// --------------------
// Admin: upload user image
// --------------------
app.post("/api/admin/user/:id/image", upload.single("image"), async (req, res) => {
  try {
    const id = req.params.id;
    if (!req.file) return res.json({ success: false, error: "No file uploaded" });
    const imagePath = "/uploads/" + req.file.filename;
    await run("UPDATE users SET image=? WHERE id=?", [imagePath, id]);
    res.json({ success: true, image: imagePath });
  } catch (err) {
    console.error("Upload image error:", err);
    res.status(500).json({ success: false });
  }
});

// --------------------
// Admin: user lessons count
// --------------------
app.get("/api/admin/user/:id/lessons", async (req, res) => {
  try {
    const id = req.params.id;
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [id]);
    res.json({ success: true, count: row ? row.c : 0 });
  } catch (err) {
    console.error("User lessons error:", err);
    res.status(500).json({ success: false });
  }
});

// --------------------
// Mark lesson complete
// --------------------
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.json({ error: "Missing fields" });

    await run("INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)", [uuidv4(), userId, lessonId]);

    const totalLessons = 4;
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [userId]);
    const percent = Math.round(((row && row.c) || 0) / totalLessons * 100);
    await run("UPDATE users SET percentage=? WHERE id=?", [percent, userId]);
    res.json({ success: true, percentage: percent });
  } catch (err) {
    console.error("Complete error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// Run code (Java/Python/JS)
// - returns JSON (never HTML) so client can parse safely
// - checks executables and returns clear error if missing
// --------------------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.json({ error: "Missing language/source" });

    // JAVAC / JAVA check
    if (language === "java") {
      const javacOk = await commandAvailable("javac");
      const javaOk = await commandAvailable("java");
      if (!javacOk || !javaOk) {
        return res.json({ error: "Java JDK not available on server. Install JDK (javac & java) to run Java code." });
      }

      // write and compile/run
      fs.writeFileSync("Main.java", source);
      try {
        await execP("javac Main.java");
      } catch (compileErr) {
        return res.json({ error: "Compilation failed: " + (compileErr.stderr || compileErr.message) });
      }
      try {
        const { stdout } = await execP("java Main");
        return res.json({ output: stdout });
      } catch (runErr) {
        return res.json({ error: "Runtime failed: " + (runErr.stderr || runErr.message) });
      }
    }

    // PYTHON check
    if (language === "python") {
      const pyOk = await commandAvailable("python") || await commandAvailable("python3");
      if (!pyOk) return res.json({ error: "Python not available on server." });

      fs.writeFileSync("script.py", source);
      try {
        const { stdout } = await execP("python script.py");
        return res.json({ output: stdout });
      } catch (e) {
        // try python3
        try {
          const { stdout } = await execP("python3 script.py");
          return res.json({ output: stdout });
        } catch (e2) {
          return res.json({ error: "Python run failed: " + (e2.stderr || e2.message) });
        }
      }
    }

    // JAVASCRIPT: evaluate safely (note: eval is still potentially dangerous)
    if (language === "javascript") {
      try {
        const result = eval(source); // keep as previously used in your project
        return res.json({ output: String(result ?? "") });
      } catch (err) {
        return res.json({ error: "JS Error: " + err.message });
      }
    }

    return res.json({ error: "Language not supported" });
  } catch (err) {
    console.error("run-code handler error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// Page route
// --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// fallback JSON for all POST endpoints so browser never gets HTML where JSON expected
app.use((req, res, next) => {
  if (req.method === "POST") return res.status(404).json({ error: "Endpoint not found" });
  next();
});

// --------------------
// Start server
// --------------------
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));
