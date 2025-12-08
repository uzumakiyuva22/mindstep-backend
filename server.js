// server.js - Final full (Cloudinary + MongoDB + Piston + Admin APIs)
// Node 18+ recommended (uses global fetch)

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const AbortController = globalThis.AbortController || require("abort-controller");

// ---------- CONFIG ----------
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");

// ---------- VERIFY REQUIRED ENV ----------
if (!process.env.MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI missing. Set it in Render / .env");
  process.exit(1);
}
if (!process.env.ADMIN_SECRET) {
  console.error("❌ ERROR: ADMIN_SECRET missing. Set it in Render / .env (needed for admin routes)");
  process.exit(1);
}

// ---------- CLOUDINARY CHECK ----------
const CLOUDINARY_URL = process.env.CLOUDINARY_URL;
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

if (!CLOUDINARY_URL && !(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET)) {
  console.error("❌ ERROR: Cloudinary credentials missing. Provide CLOUDINARY_URL or CLOUDINARY_* variables");
  process.exit(1);
}

// ---------- CLOUDINARY SETUP ----------
const cloudinary = require("cloudinary").v2;
try {
  if (CLOUDINARY_URL && CLOUDINARY_URL.startsWith("cloudinary://")) {
    cloudinary.config({ cloudinary_url: CLOUDINARY_URL, secure: true });
  } else {
    cloudinary.config({
      cloud_name: CLOUDINARY_CLOUD_NAME,
      api_key: CLOUDINARY_API_KEY,
      api_secret: CLOUDINARY_API_SECRET,
      secure: true
    });
  }
} catch (e) {
  console.error("❌ Cloudinary config error:", e && e.message ? e.message : e);
  process.exit(1);
}

// ---------- EXPRESS ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// ---------- MULTER (temp files) ----------
const tempDir = path.join(__dirname, "temp");
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
const upload = multer({ dest: tempDir, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

// ---------- MONGOOSE ----------
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err && err.message ? err.message : err);
    process.exit(1);
  });

// ---------- MODELS ----------
const userSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  image:    { type: String, default: null },
  percentage:{ type: Number, default: 0 },
  deleted:  { type: Boolean, default: false },
  created_at:{ type: Date, default: Date.now }
}, { versionKey: false });

const adminSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  created_at:{ type: Date, default: Date.now }
}, { versionKey: false });

const completionSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  user_id: { type: String, required: true },
  lesson_id: { type: String, required: true }
}, { versionKey: false });
completionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });

const User = mongoose.model("User", userSchema);
const Admin = mongoose.model("Admin", adminSchema);
const Completion = mongoose.model("Completion", completionSchema);

// ---------- DEFAULT ADMIN ----------
(async function ensureAdmin(){
  try {
    const defaultAdminUser = process.env.DEFAULT_ADMIN || "Uzumaki_Yuva";
    const defaultAdminPass = process.env.DEFAULT_ADMIN_PASS || "yuva22";
    const found = await Admin.findOne({ username: defaultAdminUser }).lean();
    if (!found) {
      await Admin.create({
        username: defaultAdminUser,
        password: bcrypt.hashSync(defaultAdminPass, 10)
      });
      console.log(`✔ Default admin created (username: ${defaultAdminUser})`);
    } else {
      console.log("✔ Default admin exists");
    }
  } catch (e) { console.error("Admin init error:", e && e.message ? e.message : e); }
})();

// ---------- ADMIN AUTH MIDDLEWARE ----------
function adminAuthMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return res.status(401).json({ success: false, error: "Unauthorized" });
  const token = header.slice(7);
  if (token !== process.env.ADMIN_SECRET) return res.status(401).json({ success: false, error: "Unauthorized" });
  req.admin = { id: "admin" };
  next();
}

// ---------- HEALTH ----------
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// ---------- UTIL: CLOUDINARY UPLOAD ----------
async function uploadToCloudinary(localPath) {
  try {
    const uploaded = await cloudinary.uploader.upload(localPath, { folder: "mindstep_users" });
    return uploaded.secure_url || uploaded.url || null;
  } catch (e) {
    console.error("Cloudinary upload error:", e && e.message ? e.message : e);
    return null;
  } finally {
    try { if (fs.existsSync(localPath)) fs.unlinkSync(localPath); } catch(e){/*ignore*/ }
  }
}

// ---------- SIGNUP ----------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

    const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
    if (exists) return res.status(409).json({ error: "User already exists" });

    let imageUrl = null;
    if (req.file) {
      imageUrl = await uploadToCloudinary(req.file.path);
    }

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image: imageUrl
    });

    const out = await User.findById(user._id).select("-password").lean();
    res.json({ success: true, user: out });
  } catch (err) {
    console.error("Signup error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Missing fields" });

    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }], deleted: false });
    if (!user) return res.status(401).json({ error: "Invalid Login" });

    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Invalid Login" });

    const out = await User.findById(user._id).select("-password").lean();
    res.json({ success: true, user: out });
  } catch (err) {
    console.error("Login error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN LOGIN (returns ADMIN_SECRET token on success) ----------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if(!username||!password) return res.status(400).json({ success:false, error: "Missing fields" });

    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(404).json({ success:false, error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password)) return res.status(401).json({ success:false, error: "Wrong password" });

    // Successful -> return admin token (ADMIN_SECRET)
    res.json({ success: true, adminToken: process.env.ADMIN_SECRET });
  } catch (err) {
    console.error("Admin login error:", err && err.message ? err.message : err);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// ---------- RUN CODE (Piston) with timeout & fallback ----------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source, stdin } = req.body || {};
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    const map = {
      java: { language: "java", version: "17" },
      python: { language: "python", version: "3.10.0" },
      javascript: { language: "javascript", version: "18.15.0" }
    };
    const entry = map[language];
    if (!entry) return res.status(400).json({ error: "Language not supported" });

    const controller = new AbortController();
    const timeoutMs = Number(process.env.PISTON_TIMEOUT_MS || 8000);
    const id = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch("https://emkc.org/api/v2/piston/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...entry,
          files: [{ name: "Main", content: source }],
          stdin: stdin || ""
        }),
        signal: controller.signal
      });

      clearTimeout(id);

      if (!response.ok) {
        const txt = await response.text().catch(()=>"");
        return res.json({ output: `⚠ Engine error: ${response.status} ${response.statusText}\n${txt}` });
      }

      const data = await response.json().catch(()=>null);
      const output = data?.run?.output ?? JSON.stringify(data ?? {});
      return res.json({ output });
    } catch (fetchErr) {
      const msg = (fetchErr && fetchErr.name === "AbortError")
        ? `⚠ Execution timed out after ${timeoutMs}ms. Try again later.`
        : `⚠ Execution service unavailable. Try client preview or try again later.`;
      console.error("Run-code fetch error:", fetchErr && fetchErr.message ? fetchErr.message : fetchErr);
      return res.json({ output: msg });
    } finally {
      clearTimeout(id);
    }
  } catch (err) {
    console.error("Run-code error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- USER INFO (flexible) ----------
app.get("/user-info/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password").lean();
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (e) {
    console.error("/user-info/:id error:", e && e.message ? e.message : e);
    res.status(500).json({ error: "Server error" });
  }
});
app.get("/user-info", async (req, res) => {
  try {
    let userId = req.query.userId || null;
    if (!userId) {
      const header = req.headers.authorization || "";
      if (header.startsWith("Bearer ")) userId = header.slice(7);
    }
    if (!userId) return res.status(400).json({ error: "Missing userId" });
    const user = await User.findById(userId).select("-password").lean();
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (e) {
    console.error("/user-info error:", e && e.message ? e.message : e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN APIs (protected by ADMIN_SECRET) ----------

// Overview
app.get("/api/admin/overview", adminAuthMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({});
    const activeCourses = Number(process.env.ACTIVE_COURSES || 5);
    const dailyVisits = Number(process.env.DAILY_VISITS || 224);
    const reports = Number(process.env.REPORTS || 3);
    res.json({ success: true, totalUsers, activeCourses, dailyVisits, reports });
  } catch (e) {
    console.error("/api/admin/overview error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// Get users
app.get("/api/admin/users", adminAuthMiddleware, async (req, res) => {
  try {
    const users = await User.find({}).lean();
    res.json({ success: true, users });
  } catch (e) {
    console.error("/api/admin/users error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// View single user + lessons done
app.get("/api/admin/user/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).lean();
    if (!user) return res.json({ success:false, error: "User not found" });
    const lessonsDone = await Completion.countDocuments({ user_id: req.params.id });
    res.json({ success:true, user, lessonsDone });
  } catch (e) {
    console.error("/api/admin/user/:id error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// Update user
app.put("/api/admin/user/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const update = {};
    if (username) update.username = username;
    if (email) update.email = email;
    if (password) update.password = bcrypt.hashSync(password, 10);
    await User.findByIdAndUpdate(req.params.id, update);
    res.json({ success:true });
  } catch (e) {
    console.error("/api/admin/user/:id PUT error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// Update user image
app.post("/api/admin/user/:id/image", adminAuthMiddleware, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.json({ success:false, error: "No image uploaded" });
    const imgUrl = await uploadToCloudinary(req.file.path);
    await User.findByIdAndUpdate(req.params.id, { image: imgUrl });
    res.json({ success:true, image: imgUrl });
  } catch (e) {
    console.error("/api/admin/user/:id/image error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// Purge user
app.post("/api/admin/user/:id/purge", adminAuthMiddleware, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Completion.deleteMany({ user_id: req.params.id });
    res.json({ success:true });
  } catch (e) {
    console.error("/api/admin/user/:id/purge error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// Reset progress
app.post("/api/admin/user/:id/reset", adminAuthMiddleware, async (req, res) => {
  try {
    await Completion.deleteMany({ user_id: req.params.id });
    await User.findByIdAndUpdate(req.params.id, { percentage: 0 });
    res.json({ success:true });
  } catch (e) {
    console.error("/api/admin/user/:id/reset error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// Lessons count
app.get("/api/admin/user/:id/lessons", adminAuthMiddleware, async (req, res) => {
  try {
    const count = await Completion.countDocuments({ user_id: req.params.id });
    res.json({ success:true, count });
  } catch (e) {
    console.error("/api/admin/user/:id/lessons error:", e && e.message ? e.message : e);
    res.json({ success:false, error: e.message });
  }
});

// Add course (simple placeholder)
app.post("/api/admin/course", adminAuthMiddleware, async (req, res) => {
  try {
    // No Course collection provided in this project — return success placeholder
    res.json({ success:true });
  } catch (e) {
    res.json({ success:false, error: e.message });
  }
});

// ---------- PROGRESS route used by main page ----------
app.post("/get-main-progress", async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: "Missing userId" });
    const user = await User.findById(userId).lean();
    return res.json({ fullStack: user?.percentage ?? 0 });
  } catch (e) {
    console.error("/get-main-progress error:", e && e.message ? e.message : e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- COMPLETE LESSON ----------
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ error: "Missing fields" });

    await Completion.updateOne(
      { user_id: userId, lesson_id: String(lessonId) },
      { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: String(lessonId) } },
      { upsert: true }
    );

    const totalLessons = Number(process.env.TOTAL_LESSONS || 4);
    const done = await Completion.countDocuments({ user_id: userId });
    const percent = Math.round((done / Math.max(1, totalLessons)) * 100);
    await User.findByIdAndUpdate(userId, { percentage: percent });

    res.json({ success: true, percentage: percent });
  } catch (err) {
    console.error("Complete error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ROOT ----------
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.sendFile(path.join(PUBLIC_DIR, "index.html"), (err) => {
    if (err) return res.send(`<h2>Backend running — put your LoginPage.html in /public</h2>`);
  });
});

// ---------- GLOBAL ERROR HANDLING & SHUTDOWN ----------
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED PROMISE REJECTION:', reason);
});
function gracefulShutdown() {
  console.log("Shutting down...");
  mongoose.disconnect().finally(() => process.exit(0));
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// ---------- START ----------
app.listen(PORT, () => console.log(`🔥 SERVER running at http://localhost:${PORT}`));
