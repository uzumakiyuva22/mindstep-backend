// server.js (final full with missing endpoints added)
require("dotenv").config();
const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");
const util = require("util");
const { exec } = require("child_process");
const execP = util.promisify(exec);

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

// sqlite helpers (promise wrappers)
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

  // default admin
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
// EXPRESS app
// --------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

// --------------------
// Multer for uploads
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
    await execP(`${cmd} -version`);
    return true;
  } catch (e1) {
    try {
      await execP(`${cmd} --version`);
      return true;
    } catch (e2) {
      return false;
    }
  }
}
function safeUnlink(filePath) {
  try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) {}
}

// --------------------
// API: signup
// --------------------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

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
    return res.json({ success: true, user });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// API: login (user)
// --------------------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Missing fields" });

    const user = await get("SELECT * FROM users WHERE username=? OR email=?", [usernameOrEmail, usernameOrEmail]);
    if (!user) return res.json({ error: "Invalid Login" });

    if (!bcrypt.compareSync(password, user.password)) return res.json({ error: "Invalid Login" });

    delete user.password;
    return res.json({ success: true, user });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// API: admin login
// --------------------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    const admin = await get("SELECT * FROM admins WHERE username=?", [username]);
    if (!admin) return res.json({ error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password)) return res.json({ error: "Wrong password" });

    delete admin.password;
    return res.json({ success: true, admin });
  } catch (err) {
    console.error("Admin login error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// Admin endpoints (existing)
// --------------------
app.get("/api/admin/users", async (req, res) => {
  try {
    const rows = await all("SELECT id, username, email, image, percentage, created_at FROM users ORDER BY created_at DESC");
    return res.json({ success: true, users: rows });
  } catch (err) {
    console.error("Fetch users error:", err);
    return res.status(500).json({ success: false });
  }
});

app.delete("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    await run("DELETE FROM completions WHERE user_id = ?", [id]);
    await run("DELETE FROM users WHERE id = ?", [id]);
    return res.json({ success: true });
  } catch (err) {
    console.error("Delete user error:", err);
    return res.status(500).json({ success: false });
  }
});

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
  } catch (err) {
    console.error("Update user error:", err);
    return res.status(500).json({ success: false });
  }
});

app.post("/api/admin/user/:id/image", upload.single("image"), async (req, res) => {
  try {
    const id = req.params.id;
    if (!req.file) return res.json({ success: false, error: "No file uploaded" });
    const imagePath = "/uploads/" + req.file.filename;
    await run("UPDATE users SET image=? WHERE id=?", [imagePath, id]);
    return res.json({ success: true, image: imagePath });
  } catch (err) {
    console.error("Upload image error:", err);
    return res.status(500).json({ success: false });
  }
});

app.get("/api/admin/user/:id/lessons", async (req, res) => {
  try {
    const id = req.params.id;
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [id]);
    return res.json({ success: true, count: row ? row.c : 0 });
  } catch (err) {
    console.error("User lessons error:", err);
    return res.status(500).json({ success: false });
  }
});

// --------------------
// MISSING ADMIN endpoints ADDED
// --------------------

// Admin overview used by AdminDashboard
app.get("/api/admin/overview", async (req, res) => {
  try {
    const totalUsersRow = await get("SELECT COUNT(*) AS c FROM users");
    const totalCoursesRow = await get("SELECT COUNT(*) AS c FROM courses");
    const totalCompletionsRow = await get("SELECT COUNT(*) AS c FROM completions");

    const totalUsers = totalUsersRow ? totalUsersRow.c : 0;
    const activeCourses = totalCoursesRow ? totalCoursesRow.c : 0;
    const totalCompletions = totalCompletionsRow ? totalCompletionsRow.c : 0;

    // Derive a simple "average progress" for display (not required but useful)
    const avgPercentRow = await get("SELECT AVG(percentage) AS avgp FROM users");
    const avgPercent = avgPercentRow ? Math.round(avgPercentRow.avgp || 0) : 0;

    return res.json({
      success: true,
      totalUsers,
      activeCourses,
      dailyVisits: 224, // static placeholder
      reports: 3,       // static placeholder
      totalCompletions,
      averageProgress: avgPercent
    });
  } catch (err) {
    console.error("admin overview error:", err);
    return res.status(500).json({ success: false });
  }
});

// Get user (full) used by AdminDashboard when opening a user
app.get("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const user = await get("SELECT id, username, email, image, percentage, created_at FROM users WHERE id=?", [id]);
    if (!user) return res.json({ success: false, error: "User not found" });
    const lessonsRow = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [id]);
    const lessonsDone = lessonsRow ? lessonsRow.c : 0;
    return res.json({ success: true, user, lessonsDone });
  } catch (err) {
    console.error("admin get user error:", err);
    return res.status(500).json({ success: false });
  }
});

// Reset a user's progress (delete completions and set percentage 0)
app.post("/api/admin/user/:id/reset", async (req, res) => {
  try {
    const id = req.params.id;
    await run("DELETE FROM completions WHERE user_id=?", [id]);
    await run("UPDATE users SET percentage=0 WHERE id=?", [id]);
    return res.json({ success: true });
  } catch (err) {
    console.error("admin reset user error:", err);
    return res.status(500).json({ success: false });
  }
});

// --------------------
// Mark lesson complete
// --------------------
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ error: "Missing fields" });

    await run("INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?, ?, ?)", [uuidv4(), userId, lessonId]);

    const totalLessons = 4;
    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id=?", [userId]);
    const percent = Math.round(((row && row.c) || 0) / totalLessons * 100);
    await run("UPDATE users SET percentage=? WHERE id=?", [percent, userId]);
    return res.json({ success: true, percentage: percent });
  } catch (err) {
    console.error("Complete error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// Run code (Java / Python / JS) with Java PATH fallback
// --------------------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    // fallback JDK paths — adjust if your JDK folder differs
    const JAVAC_FALLBACK = `"C:\\Program Files\\Java\\jdk-17\\bin\\javac.exe"`;
    const JAVA_FALLBACK  = `"C:\\Program Files\\Java\\jdk-17\\bin\\java.exe"`;
    const JAVAC_FALLBACK2 = `"C:\\Program Files\\Java\\jdk-17.0.12\\bin\\javac.exe"`;
    const JAVA_FALLBACK2  = `"C:\\Program Files\\Java\\jdk-17.0.12\\bin\\java.exe"`;

    // ----- JAVA -----
    if (language === "java") {
      // test system path first
      const javacOk = await commandAvailable("javac");
      const javaOk  = await commandAvailable("java");

      // choose commands (prefer system)
      let javacCmd = javacOk ? "javac" : (fs.existsSync("C:\\Program Files\\Java\\jdk-17\\bin\\javac.exe") ? JAVAC_FALLBACK : JAVAC_FALLBACK2);
      let javaCmd  = javaOk  ? "java"  : (fs.existsSync("C:\\Program Files\\Java\\jdk-17\\bin\\java.exe") ? JAVA_FALLBACK : JAVA_FALLBACK2);

      // if still missing, respond error
      try {
        // quick check
        await execP(`${javacCmd} -version`).catch(()=>{});
        await execP(`${javaCmd} -version`).catch(()=>{});
      } catch {}

      // still attempt to run — if system truly has none, this will throw and we return error
      const javaFile = path.join(__dirname, "Main.java");
      const classFile = path.join(__dirname, "Main.class");
      try {
        fs.writeFileSync(javaFile, source, "utf8");
        await execP(`${javacCmd} "${javaFile}"`);
      } catch (compileErr) {
        safeUnlink(javaFile); safeUnlink(classFile);
        const msg = (compileErr.stderr || compileErr.message || String(compileErr)).toString();
        return res.json({ error: "Compilation failed: " + msg });
      }

      try {
        const { stdout } = await execP(`${javaCmd} -cp "${__dirname}" Main`);
        return res.json({ output: stdout });
      } catch (runErr) {
        const msg = (runErr.stderr || runErr.message || String(runErr)).toString();
        return res.json({ error: "Runtime failed: " + msg });
      } finally {
        safeUnlink(javaFile);
        safeUnlink(classFile);
      }
    }

    // ----- PYTHON -----
    if (language === "python") {
      const pyOkA = await commandAvailable("python");
      const pyOkB = await commandAvailable("python3");
      if (!pyOkA && !pyOkB) return res.json({ error: "Python not available on server." });

      const pythonCmd = pyOkA ? "python" : "python3";
      const pyFile = path.join(__dirname, "script.py");
      try {
        fs.writeFileSync(pyFile, source, "utf8");
        const { stdout } = await execP(`${pythonCmd} "${pyFile}"`);
        return res.json({ output: stdout });
      } catch (e) {
        const msg = (e.stderr || e.message || String(e)).toString();
        return res.json({ error: "Python run failed: " + msg });
      } finally {
        safeUnlink(path.join(__dirname, "script.py"));
      }
    }

    // ----- JAVASCRIPT -----
    if (language === "javascript") {
      try {
        const result = eval(source);
        return res.json({ output: String(result ?? "") });
      } catch (err) {
        return res.json({ error: "JS Error: " + err.message });
      }
    }

    return res.json({ error: "Language not supported" });
  } catch (err) {
    console.error("run-code handler error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// Course-related endpoints (used by course.html & main page)
// --------------------

// Return progress for a given username + course (course kept for compatibility)
app.post("/get-progress", async (req, res) => {
  try {
    const { username, course } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });

    const user = await get("SELECT id, username, percentage FROM users WHERE username = ?", [username]);
    if (!user) return res.json({ success:false, error: "User not found" });

    const comp = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [user.id]);
    const lessonsCompleted = comp ? comp.c : 0;
    return res.json({ success: true, percentage: user.percentage || 0, lessonsCompleted });
  } catch (e) {
    console.error("get-progress error:", e);
    return res.status(500).json({ success:false, error: "Server error" });
  }
});

// Save progress (username, course, percentage, lessons_completed)
app.post("/save-progress", async (req, res) => {
  try {
    const { username, course, percentage, lessons_completed } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });

    const user = await get("SELECT id FROM users WHERE username = ?", [username]);
    if (!user) return res.json({ success:false, error: "User not found" });

    const uid = user.id;
    // create completions rows for lessons 1..lessons_completed
    const n = Math.max(0, Number(lessons_completed || 0));
    for (let i = 1; i <= n; i++) {
      await run("INSERT OR IGNORE INTO completions (id, user_id, lesson_id) VALUES (?,?,?)", [uuidv4(), uid, String(i)]);
    }

    // update percentage
    const pct = Math.max(0, Math.min(100, Number(percentage || 0)));
    await run("UPDATE users SET percentage=? WHERE id=?", [pct, uid]);

    return res.json({ success: true, percentage: pct, lessons_completed: n });
  } catch (e) {
    console.error("save-progress error:", e);
    return res.status(500).json({ success:false, error: "Server error" });
  }
});

// Recompute percentage from completions and update users.percentage (used by course page)
app.post("/update-main-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });

    const user = await get("SELECT id FROM users WHERE username = ?", [username]);
    if (!user) return res.json({ success:false, error: "User not found" });

    const row = await get("SELECT COUNT(*) AS c FROM completions WHERE user_id = ?", [user.id]);
    const totalLessons = 4;
    const percent = Math.round(((row && row.c) || 0) / totalLessons * 100);
    await run("UPDATE users SET percentage=? WHERE id=?", [percent, user.id]);

    return res.json({ success:true, percentage: percent });
  } catch (e) {
    console.error("update-main-progress error:", e);
    return res.status(500).json({ success:false, error: "Server error" });
  }
});

// Return main progress for MainPage (simple endpoint)
app.post("/get-main-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });

    const user = await get("SELECT percentage FROM users WHERE username = ?", [username]);
    return res.json({ success: true, fullStack: (user ? user.percentage : 0) || 0 });
  } catch (e) {
    console.error("get-main-progress error:", e);
    return res.status(500).json({ success:false, error: "Server error" });
  }
});

// Simple public summary used by course.html fetch("/progress")
app.get("/progress", async (req, res) => {
  try {
    const usersRow = await get("SELECT COUNT(*) AS c FROM users");
    const usersCount = usersRow ? usersRow.c : 0;
    const completionsRow = await get("SELECT COUNT(*) AS c FROM completions");
    const totalCompletions = completionsRow ? completionsRow.c : 0;

    // compute rough percentage average across all users (if users exist)
    const avgPercentRow = await get("SELECT AVG(percentage) AS avgp FROM users");
    const avgPct = avgPercentRow ? Math.round(avgPercentRow.avgp || 0) : 0;

    return res.json({ percentage: avgPct, completed: totalCompletions, users: usersCount });
  } catch (e) {
    console.error("progress summary error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// --------------------
// default page & fallback
// --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// Ensure POST endpoints always receive JSON or JSON-error (no accidental HTML)
app.use((req, res, next) => {
  if (req.method === "POST") return res.status(404).json({ error: "Endpoint not found" });
  next();
});

// --------------------
// Start server
// --------------------
app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));
