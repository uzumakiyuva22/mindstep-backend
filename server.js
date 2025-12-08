// server.js - Updated (Cloudinary + MongoDB + admin endpoints)
// Node 18+ (uses global fetch)

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const cloudinaryLib = require("cloudinary").v2;

// CONFIG
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");

// ENV check
if (!process.env.MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI missing.");
  process.exit(1);
}
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;
const CLOUDINARY_URL = process.env.CLOUDINARY_URL;
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;
if (!CLOUDINARY_URL && !(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET)) {
  console.error("❌ ERROR: Cloudinary credentials missing.");
  process.exit(1);
}

// Cloudinary config
try {
  if (CLOUDINARY_URL && CLOUDINARY_URL.startsWith("cloudinary://")) {
    cloudinaryLib.config({ cloudinary_url: CLOUDINARY_URL, secure: true });
  } else {
    cloudinaryLib.config({
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

// EXPRESS
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// MULTER
const tempDir = path.join(__dirname, "temp");
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
const upload = multer({ dest: tempDir, limits: { fileSize: 10 * 1024 * 1024 } });

// MONGOOSE
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB connection error:", err && err.message ? err.message : err); process.exit(1); });

// SCHEMAS
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

// Ensure default admin exists
(async function ensureAdmin(){
  try {
    const defaultAdminUser = "Uzumaki_Yuva";
    const found = await Admin.findOne({ username: defaultAdminUser }).lean();
    if (!found) {
      await Admin.create({
        username: defaultAdminUser,
        password: bcrypt.hashSync("yuva22", 10)
      });
      console.log(`✔ Default admin created (username: ${defaultAdminUser})`);
    } else {
      console.log("✔ Default admin exists");
    }
  } catch (e) { console.error("Admin init error:", e && e.message ? e.message : e); }
})();

// Admin auth middleware expects Authorization: Bearer <ADMIN_SECRET>
function adminAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!ADMIN_SECRET) return res.status(403).json({ error: "Admin routes not enabled (set ADMIN_SECRET)" });
  if (!token || token !== ADMIN_SECRET) return res.status(401).json({ error: "Unauthorized" });
  req.admin = { id: "admin" };
  next();
}

// HEALTH
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// SIGNUP (image -> Cloudinary)
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });
    const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
    if (exists) return res.status(409).json({ error: "User already exists" });

    let imageUrl = null;
    if (req.file) {
      try {
        const uploaded = await cloudinaryLib.uploader.upload(req.file.path, { folder: "mindstep_users" });
        imageUrl = uploaded.secure_url || uploaded.url || null;
      } catch (upErr) {
        console.error("Cloudinary upload error:", upErr && upErr.message ? upErr.message : upErr);
      } finally {
        if (req.file && req.file.path && fs.existsSync(req.file.path)) try { fs.unlinkSync(req.file.path); } catch(e){}
      }
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

// LOGIN
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

// ADMIN LOGIN - returns admin info and ADMIN_SECRET so frontend can use admin routes
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if(!username||!password) return res.status(400).json({ error: "Missing fields" });

    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(404).json({ error: "Admin not found" });
    if (!bcrypt.compareSync(password, admin.password)) return res.status(401).json({ error: "Wrong password" });

    // Return admin + secret (frontend stores admin_token = ADMIN_SECRET)
    res.json({ success: true, admin: { id: admin._id, username: admin.username }, adminSecret: ADMIN_SECRET || null });
  } catch (err) {
    console.error("Admin login error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// RUN CODE (Piston)
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    const map = {
      java: { language: "java", version: "17" },
      python: { language: "python", version: "3.10.0" },
      javascript: { language: "javascript", version: "18.15.0" }
    };
    if (!map[language]) return res.status(400).json({ error: "Language not supported" });

    const response = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...map[language],
        files: [{ name: "Main", content: source }]
      })
    });
    const data = await response.json();
    res.json({ output: data.run?.output ?? JSON.stringify(data) });
  } catch (err) {
    console.error("Run-code error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN API ENDPOINTS (protected) ----------
app.get("/api/admin/overview", adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({});
    // for demo purposes: activeCourses / dailyVisits / reports are static
    res.json({ success: true, totalUsers, activeCourses: 5, dailyVisits: 224, reports: 3 });
  } catch (e) {
    console.error("/api/admin/overview error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, "-password").sort({ created_at: -1 }).lean();
    res.json({ success: true, users });
  } catch (e) {
    console.error("/api/admin/users error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findById(id).select("-password").lean();
    if (!user) return res.json({ success: false, error: "User not found" });
    const lessonsDone = await Completion.countDocuments({ user_id: id });
    res.json({ success: true, user, lessonsDone });
  } catch (e) {
    console.error("/api/admin/user/:id error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { username, email, password } = req.body;
    const update = {};
    if (username) update.username = username;
    if (email) update.email = email;
    if (password) update.password = bcrypt.hashSync(password, 10);
    await User.findByIdAndUpdate(id, update);
    res.json({ success: true });
  } catch (e) {
    console.error("PUT /api/admin/user/:id error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// upload user image (admin)
app.post("/api/admin/user/:id/image", adminAuth, upload.single("image"), async (req, res) => {
  const id = req.params.id;
  if (!req.file) return res.status(400).json({ error: "Missing file" });
  try {
    const uploaded = await cloudinaryLib.uploader.upload(req.file.path, { folder: "mindstep_users" });
    const url = uploaded.secure_url || uploaded.url || null;
    await User.findByIdAndUpdate(id, { image: url });
    if (req.file && req.file.path && fs.existsSync(req.file.path)) try { fs.unlinkSync(req.file.path); } catch(_) {}
    res.json({ success: true, image: url });
  } catch (e) {
    console.error("Cloudinary upload error:", e && e.message ? e.message : e);
    if (req.file && req.file.path && fs.existsSync(req.file.path)) try { fs.unlinkSync(req.file.path); } catch(_) {}
    res.status(500).json({ success: false, error: "Cloudinary upload error: " + (e && e.message ? e.message : e) });
  }
});

app.post("/api/admin/user/:id/purge", adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    await User.findByIdAndDelete(id);
    await Completion.deleteMany({ user_id: id });
    res.json({ success: true });
  } catch (e) {
    console.error("Purge error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/user/:id/reset", adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    await Completion.deleteMany({ user_id: id });
    await User.findByIdAndUpdate(id, { percentage: 0 });
    res.json({ success: true });
  } catch (e) {
    console.error("Reset error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// complete lesson
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ error: "Missing fields" });
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
  } catch (err) {
    console.error("Complete error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// get main progress by username or userId (frontend uses different calls)
app.post("/get-main-progress", async (req, res) => {
  try {
    const { username, userId } = req.body;
    let user;
    if (userId) user = await User.findById(userId).lean();
    else if (username) user = await User.findOne({ username }).lean();
    if (!user) return res.json({ fullStack: 0 });
    res.json({ fullStack: user.percentage || 0 });
  } catch (e) {
    console.error("/get-main-progress error:", e);
    res.status(500).json({ fullStack: 0 });
  }
});

// get user by id (used by MainPage)
app.get("/api/get-user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findById(id).select("-password").lean();
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (e) {
    console.error("/api/get-user/:id error:", e);
    res.status(500).json({ error: "Server error" });
  }
});
app.get("/test-cloud", async (req, res) => {
  try {
    const r = await cloudinary.v2.uploader.upload("https://via.placeholder.com/150");
    res.json(r);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ROOT
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send(`<h2>Backend running — put your LoginPage.html in /public</h2>`);
});

// graceful & start
process.on('uncaughtException', (err) => console.error('UNCAUGHT EXCEPTION:', err));
process.on('unhandledRejection', (r) => console.error('UNHANDLED PROMISE REJECTION:', r));
function gracefulShutdown(){ mongoose.disconnect().finally(()=>process.exit(0)); }
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

app.listen(PORT, () => console.log(`🔥 SERVER running at http://localhost:${PORT}`));
