
/**
 * server.js — Final MindStep backend (CLOUDINARY + MONGODB + PISTON remote Java21)
 * Node 18+ (global fetch available)
 *
 * Features:
 *  - Cloudinary image uploads (CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME/API_KEY/SECRET)
 *  - MongoDB via MONGO_URI
 *  - Signup / Login (bcrypt)
 *  - Admin endpoints protected by ADMIN_SECRET (set in env)
 *  - Run code endpoint using remote Piston (Java 21, Python, JS)
 *  - Clean temp file handling
 *  - Clear error reporting for missing envs
 *
 * Deploy notes:
 *  - Set MONGO_URI and either CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET
 *  - (Optional) set ADMIN_SECRET
 *  - No local Java/javac required: Java code executes remotely via Piston API (emkc.org)
 */

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const cloudinary = require("cloudinary").v2;
const util = require("util");
const { execFile } = require("child_process");
const execFileP = util.promisify(execFile);

// ---------- CONFIG ----------
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const TEMP_DIR = path.join(__dirname, "temp");

// ensure temp directory
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// ---------- ENV CHECK ----------
if (!process.env.MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI is required in environment.");
  process.exit(1);
}
if (
  !process.env.CLOUDINARY_URL &&
  !(
    process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
  )
) {
  console.error(
    "❌ ERROR: Cloudinary credentials missing. Provide CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET"
  );
  process.exit(1);
}

// CLOUDINARY CONFIG
try {
  if (process.env.CLOUDINARY_URL) {
    cloudinary.config({ cloudinary_url: process.env.CLOUDINARY_URL, secure: true });
  } else {
    cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
      secure: true,
    });
  }
} catch (e) {
  console.error("❌ Cloudinary config error:", e && e.message ? e.message : e);
  process.exit(1);
}

// ---------- MONGODB ----------
mongoose.set("strictQuery", false);
// Global error handlers to aid debugging of silent exits
process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at:', p, reason && reason.stack ? reason.stack : reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err && err.stack ? err.stack : err);
});
mongoose
  .connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("✔ MongoDB connected");
    // Seed courses on startup if seed script exists
    try {
      const seed = require("./seeds/seed.js");
      if (typeof seed === "function") await seed();
    } catch (e) {
      console.warn("Seed warning:", e && e.message ? e.message : e);
    }

    // Log current courses (count + slugs) to help debugging if frontend shows no lessons
    try {
      const Course = require("./models/Course");
      const courses = await Course.find({}).lean();
      console.log(`Courses in DB: ${courses.length}`);
      if (courses.length > 0) console.log(`Course slugs: ${courses.map((c) => c.slug).join(", ")}`);
    } catch (e) {
      console.warn("Course log error:", e && e.message ? e.message : e);
    }
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err && err.message ? err.message : err);
    process.exit(1);
  });

// ---------- EXPRESS SETUP ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// MULTER for uploads
const upload = multer({ dest: TEMP_DIR, limits: { fileSize: 10 * 1024 * 1024 } });

// ---------- HELPERS ----------
function safeUnlink(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (e) {
    // ignore
  }
}

// Remote Piston runner (public endpoint)
async function runOnPiston(language, version, files) {
  const resp = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language, version, files }),
  });

  const data = await resp.json();
  return {
      output: data.run?.stdout || data.run?.output || data.run?.stderr || ""
  };
}


// ---------- DB SCHEMAS ----------
const userSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    image: { type: String, default: null },
    percentage: { type: Number, default: 0 },
    deleted: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now },
  },
  { versionKey: false }
);

const adminSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
  },
  { versionKey: false }
);

const completionSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    user_id: { type: String, required: true },
    lesson_id: { type: String, required: true },
  },
  { versionKey: false }
);
completionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });

const User = mongoose.model("User", userSchema);
const Admin = mongoose.model("Admin", adminSchema);
const Completion = mongoose.model("Completion", completionSchema);

// Import external models
const Course = require("./models/Course");
const Lesson = require("./models/Lesson");

// ---------- DEFAULT ADMIN (create if missing) ----------
(async () => {
  try {
    const defaultAdmin = "Uzumaki_Yuva";
    const a = await Admin.findOne({ username: defaultAdmin }).lean();
    if (!a) {
      await Admin.create({
        username: defaultAdmin,
        password: bcrypt.hashSync("yuva22", 10),
      });
      console.log("✔ Default admin created (Uzumaki_Yuva)");
    } else {
      console.log("✔ Default admin exists");
    }
  } catch (e) {
    console.error("Admin init error:", e && e.message ? e.message : e);
  }
})();

// ---------- ADMIN AUTH ----------
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;
function adminAuth(req, res, next) {
  if (!ADMIN_SECRET) return res.status(403).json({ error: "Admin routes disabled (ADMIN_SECRET missing)" });
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || token !== ADMIN_SECRET) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// ---------- ROUTES ----------

// Health
app.get("/health", async (req, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

// Signup (image -> Cloudinary)
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success: false, error: "Missing fields" });

    const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
    if (exists) return res.status(409).json({ success: false, error: "User already exists" });

    let imageUrl = null;
    if (req.file) {
      try {
        const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
        imageUrl = uploaded.secure_url || uploaded.url || null;
      } catch (e) {
        console.error("Cloudinary upload error (signup):", e && e.message ? e.message : e);
      } finally {
        safeUnlink(req.file.path);
      }
    }

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image: imageUrl,
    });

    const out = { _id: user._id, username: user.username, email: user.email, image: user.image };
    res.json({ success: true, user: out });
  } catch (err) {
    console.error("Signup error:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ success: false, error: "Missing fields" });

    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }], deleted: false });
    if (!user) return res.status(401).json({ success: false, error: "Invalid credentials" });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, error: "Invalid credentials" });

    const out = { _id: user._id, username: user.username, email: user.email, image: user.image, percentage: user.percentage };
    res.json({ success: true, user: out });
  } catch (e) {
    console.error("Login error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Admin login (returns adminSecret so frontend can store admin_token)
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: "Missing fields" });

    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(404).json({ success: false, error: "Admin not found" });
    if (!bcrypt.compareSync(password, admin.password)) return res.status(401).json({ success: false, error: "Wrong password" });

    res.json({ success: true, admin: { id: admin._id, username: admin.username }, adminSecret: ADMIN_SECRET || null });
  } catch (e) {
    console.error("Admin login error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Admin overview
app.get("/api/admin/overview", adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({});
    res.json({ success: true, totalUsers, activeCourses: 5, dailyVisits: 224, reports: 3 });
  } catch (e) {
    console.error("/api/admin/overview error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// List users
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, "-password").sort({ created_at: -1 }).lean();
    res.json({ success: true, users });
  } catch (e) {
    console.error("/api/admin/users error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single user
app.get("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const u = await User.findById(req.params.id).select("-password").lean();
    if (!u) return res.status(404).json({ success: false, error: "User not found" });
    const lessonsDone = await Completion.countDocuments({ user_id: u._id });
    res.json({ success: true, user: u, lessonsDone });
  } catch (e) {
    console.error("/api/admin/user/:id error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Edit user
app.put("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const update = {};
    if (req.body.username) update.username = req.body.username;
    if (req.body.email) update.email = req.body.email;
    if (req.body.password) update.password = bcrypt.hashSync(req.body.password, 10);
    await User.findByIdAndUpdate(req.params.id, update);
    res.json({ success: true });
  } catch (e) {
    console.error("PUT /api/admin/user/:id error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Admin upload user image
app.post("/api/admin/user/:id/image", adminAuth, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: "No file" });
    const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
    const url = uploaded.secure_url || uploaded.url || null;
    await User.findByIdAndUpdate(req.params.id, { image: url });
    safeUnlink(req.file.path);
    res.json({ success: true, image: url });
  } catch (e) {
    console.error("admin image upload error:", e && e.message ? e.message : e);
    safeUnlink(req.file && req.file.path);
    res.status(500).json({ success: false, error: "Upload failed" });
  }
});

// Purge user
app.post("/api/admin/user/:id/purge", adminAuth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Completion.deleteMany({ user_id: req.params.id });
    res.json({ success: true });
  } catch (e) {
    console.error("Purge error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Reset progress
app.post("/api/admin/user/:id/reset", adminAuth, async (req, res) => {
  try {
    await Completion.deleteMany({ user_id: req.params.id });
    await User.findByIdAndUpdate(req.params.id, { percentage: 0 });
    res.json({ success: true });
  } catch (e) {
    console.error("Reset error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Complete lesson (user)
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ success: false, error: "Missing fields" });

    await Completion.updateOne(
      { user_id: userId, lesson_id: String(lessonId) },
      { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: String(lessonId) } },
      { upsert: true }
    );

    const totalLessons = 4;
    const done = await Completion.countDocuments({ user_id: userId });
    const percent = Math.round((done / totalLessons) * 100);
    await User.findByIdAndUpdate(userId, { percentage: percent });

    res.json({ success: true, percentage: percent });
  } catch (e) {
    console.error("Complete error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get user (public)
app.get("/api/get-user/:id", async (req, res) => {
  try {
    const u = await User.findById(req.params.id).select("-password").lean();
    if (!u) return res.status(404).json({ error: "User not found" });
    res.json(u);
  } catch (e) {
    console.error("/api/get-user error:", e && e.message ? e.message : e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- RUN CODE (REMOTE PISTON) ----------
// This implementation always uses the Piston remote engine (no local javac/java required).
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body || {};
    if (!language || !source) return res.status(400).json({ error: "Missing language or source" });

    if (language === "java") {
      // always run on remote Piston Java 21
      const m = source.match(/public\s+class\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
      const className = m ? m[1] : "Main";

      const remote = await runOnPiston("java", "21.0.2", [
        { name: `${className}.java`, content: source }
      ]);

      if (remote.output) return res.json({ output: remote.output });
      if (remote.error) return res.status(500).json({ error: "Remote Java execution failed: " + remote.error });
      return res.status(500).json({ error: "Unknown Java remote error" });
      return res.status(500).json({
        error: "Remote Java execution failed: " + (remote.error || "Unknown")
      });
    }

    if (language === "python") {
      const remote = await runOnPiston("python", "3.10.0", [{ name: "script.py", content: source }]);
      if (remote.output) return res.json({ output: remote.output });
      if (remote.error) return res.status(500).json({ error: "Remote Python execution failed: " + remote.error });
      return res.status(500).json({ error: "Unknown Python remote error" });
    }

    if (language === "javascript") {
      try {
        // For JS we can run remotely as well, but quick local eval (not secure) or remote fallback.
        // We'll run remote to keep behaviour consistent and sandboxed.
        const remote = await runOnPiston("javascript", "18.15.0", [{ name: "script.js", content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        if (remote.error) return res.status(500).json({ error: "Remote JS execution failed: " + remote.error });
        return res.status(500).json({ error: "Unknown JS remote error" });
      } catch (e) {
        console.error("JS remote error:", e && e.message ? e.message : e);
        return res.status(500).json({ error: "Server error running JS" });
      }
    }

    return res.status(400).json({ error: "Language not supported" });
  } catch (err) {
    console.error("run-code handler failed:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "Server error" });
  }
});

// Root serve public LoginPage.html if available

// Get course and its lessons by slug
app.get("/api/course/:slug/lessons", async (req, res) => {
  try {
    const { slug } = req.params;
    const course = await Course.findOne({ slug }).lean();
    if (!course) return res.status(404).json({ success: false, error: "Course not found" });

    const lessons = await Lesson.find({ course_id: course._id }).sort({ order: 1 }).lean();
    res.json({ success: true, course, lessons });
  } catch (e) {
    console.error("/api/course/:slug/lessons error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get user progress for a course
app.get("/api/course/:slug/progress/:userId", async (req, res) => {
  try {
    const { slug, userId } = req.params;
    const course = await Course.findOne({ slug }).lean();
    if (!course) return res.status(404).json({ success: false, error: "Course not found" });

    const completions = await Completion.countDocuments({ user_id: userId, course_id: course._id }).lean();
    const totalLessons = await Lesson.countDocuments({ course_id: course._id });
    const percent = totalLessons > 0 ? Math.round((completions / totalLessons) * 100) : 0;

    res.json({ success: true, percent, completions, totalLessons });
  } catch (e) {
    console.error("/api/course/:slug/progress/:userId error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send("<h3>MindStep backend running</h3><p>Place your frontend files in /public</p>");
});

// ---------- START SERVER ----------
const server = app.listen(PORT, () => console.log(`🔥 Server running on http://localhost:${PORT}`));
server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(`Port ${PORT} already in use.`);
    process.exit(1);
  }
  console.error("Server error:", err && err.message ? err.message : err);
  process.exit(1);
});

// Public listing of courses with lesson counts (used by MainPage)
app.get('/api/public/courses', async (req, res) => {
  try {
    const courses = await Course.find({}).lean();
    const results = [];
    for (const c of courses) {
      let lessonCount = 0;
      try {
        if (mongoose.Types.ObjectId.isValid(c._id)) {
          lessonCount = await Lesson.countDocuments({ course_id: mongoose.Types.ObjectId(c._id) });
        } else {
          // Fallback when course._id is a string (legacy UUIDs) — count by string value
          lessonCount = await Lesson.countDocuments({ course_id: String(c._id) });
        }
      } catch (countErr) {
        console.warn('/api/public/courses - count error for', c._id, countErr && countErr.message ? countErr.message : countErr);
        lessonCount = 0;
      }
      results.push({ course: c, lessonCount });
    }
    return res.json({ success: true, results });
  } catch (e) {
    console.error('/api/public/courses error:', e && e.message ? e.message : e);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});