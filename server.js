// server.js - Final (Cloudinary + MongoDB + Piston runner)
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

// ---------- CONFIG ----------
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");

// ---------- VERIFY ENV ----------
if (!process.env.MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI missing. Set it in Render / .env");
  process.exit(1);
}

if (!process.env.ADMIN_SECRET) {
  console.error("❌ ERROR: ADMIN_SECRET missing. Set it in Render / .env (needed for admin routes)");
  process.exit(1);
}

// Cloudinary may be provided in two ways. We'll accept both.
const CLOUDINARY_URL = process.env.CLOUDINARY_URL;
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

if (!CLOUDINARY_URL && !(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET)) {
  console.error("❌ ERROR: Cloudinary credentials missing. Provide CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET");
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
app.use(express.json({ limit: "30mb" }));
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

// ---------- SCHEMAS / MODELS ----------
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

// ---------- SIMPLE ADMIN AUTH MIDDLEWARE ----------
function adminAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  const adminSecret = process.env.ADMIN_SECRET || null;

  if (!adminSecret) {
    return res.status(403).json({ success:false, error: "Admin routes not enabled (ADMIN_SECRET missing)" });
  }
  if (!token || token !== adminSecret) return res.status(401).json({ success:false, error: "Unauthorized" });
  req.admin = { id: "admin", username: "admin" };
  next();
}

// ---------- HEALTH ----------
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// ---------- SIGNUP (image -> Cloudinary) ----------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success:false, error: "Missing fields" });

    const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
    if (exists) return res.status(409).json({ success:false, error: "User already exists" });

    let imageUrl = null;
    if (req.file) {
      try {
        const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
        imageUrl = uploaded.secure_url || uploaded.url || null;
      } catch (upErr) {
        console.error("Cloudinary upload error:", upErr && upErr.message ? upErr.message : upErr);
      } finally {
        if (req.file && req.file.path && fs.existsSync(req.file.path)) {
          try { fs.unlinkSync(req.file.path); } catch(e){/*ignore*/ }
        }
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
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ success:false, error: "Missing fields" });

    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }], deleted: false });
    if (!user) return res.status(401).json({ success:false, error: "Invalid Login" });

    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success:false, error: "Invalid Login" });

    const out = await User.findById(user._id).select("-password").lean();
    // For simplicity we return user object and we recommend client store userId in localStorage
    res.json({ success: true, user: out });
  } catch (err) {
    console.error("Login error:", err && err.message ? err.message : err);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// ---------- ADMIN LOGIN (returns admin token = ADMIN_SECRET) ----------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if(!username||!password) return res.status(400).json({ success:false, error: "Missing fields" });

    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(404).json({ success:false, error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password)) return res.status(401).json({ success:false, error: "Wrong password" });

    // Return the ADMIN_SECRET as adminToken for frontend to store.
    res.json({ success: true, adminToken: process.env.ADMIN_SECRET, admin: { username: admin.username, id: admin._id } });
  } catch (err) {
    console.error("Admin login error:", err && err.message ? err.message : err);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// ---------- RUN CODE (Piston) ----------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.status(400).json({ success:false, error: "Missing language/source" });

    const map = {
      java: { language: "java", version: "17" },
      python: { language: "python", version: "3.10.0" },
      javascript: { language: "javascript", version: "18.15.0" }
    };
    if (!map[language]) return res.status(400).json({ success:false, error: "Language not supported" });

    const response = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...map[language],
        files: [{ name: "Main", content: source }]
      }),
      // no special timeout here; piston returns output or an error
    });

    const data = await response.json();
    res.json({ success: true, output: data.run?.output ?? JSON.stringify(data) });
  } catch (err) {
    console.error("Run-code error:", err && err.message ? err.message : err);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// ---------- PUBLIC USER INFO ----------
app.get("/user-info/:id", async (req, res) => {
  try {
    const id = String(req.params.id);
    if(!id) return res.status(400).json({ success:false, error: "Missing id" });

    const user = await User.findById(id).select("-password").lean();
    if(!user) return res.status(404).json({ success:false, error: "User not found" });

    res.json(user);
  } catch(e){
    console.error("/user-info error:", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// get-main-progress used by your MainPage (POST { username })
app.post("/get-main-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if(!username) return res.status(400).json({ success:false, error: "Missing username" });

    const user = await User.findOne({ username }).lean();
    if(!user) return res.json({ success: true, fullStack: user?.percentage ?? 0 });

    res.json({ success: true, fullStack: user.percentage || 0 });
  } catch(e) {
    console.error("get-main-progress error", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// ---------- ADMIN APIS (protected via adminAuth) ----------
app.get("/api/admin/overview", adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({ deleted: false });
    const activeCourses = 0; // placeholder, implement courses collection if needed
    const dailyVisits = 0;
    const reports = 0;
    res.json({ success: true, totalUsers, activeCourses, dailyVisits, reports });
  } catch(e){
    console.error("/api/admin/overview", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const users = await User.find({ deleted: false }).select("-password").lean();
    res.json({ success: true, users });
  } catch(e){
    console.error("/api/admin/users", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

app.get("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const id = String(req.params.id);
    const user = await User.findById(id).select("-password").lean();
    if(!user) return res.status(404).json({ success:false, error: "User not found" });
    const lessonsDone = await Completion.countDocuments({ user_id: id });
    res.json({ success: true, user, lessonsDone });
  } catch(e){
    console.error("/api/admin/user/:id", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

app.put("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const id = String(req.params.id);
    const { username, email, password } = req.body;
    const update = {};
    if(username) update.username = username;
    if(email) update.email = email;
    if(password) update.password = bcrypt.hashSync(password, 10);
    await User.findByIdAndUpdate(id, update);
    res.json({ success: true });
  } catch(e){
    console.error("/api/admin/user PUT", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// upload image for user (admin)
app.post("/api/admin/user/:id/image", adminAuth, upload.single("image"), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!req.file) return res.status(400).json({ success:false, error: "Missing file" });

    const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
    const url = uploaded.secure_url || uploaded.url || null;
    await User.findByIdAndUpdate(id, { image: url });

    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try { fs.unlinkSync(req.file.path); } catch(e){/*ignore*/ }
    }

    res.json({ success: true, image: url });
  } catch(e){
    console.error("/api/admin/user/image", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// purge user
app.post("/api/admin/user/:id/purge", adminAuth, async (req, res) => {
  try {
    const id = String(req.params.id);
    // physically remove: remove completions and user
    await Completion.deleteMany({ user_id: id });
    await User.findByIdAndDelete(id);
    res.json({ success: true });
  } catch(e){
    console.error("/api/admin/user/purge", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// reset progress
app.post("/api/admin/user/:id/reset", adminAuth, async (req, res) => {
  try {
    const id = String(req.params.id);
    await Completion.deleteMany({ user_id: id });
    await User.findByIdAndUpdate(id, { percentage: 0 });
    res.json({ success: true });
  } catch(e){
    console.error("/api/admin/user/reset", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// lessons count
app.get("/api/admin/user/:id/lessons", adminAuth, async (req, res) => {
  try {
    const id = String(req.params.id);
    const count = await Completion.countDocuments({ user_id: id });
    res.json({ success: true, count });
  } catch(e){
    console.error("/api/admin/user/lessons", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// create a course (simple stub)
app.post("/api/admin/course", adminAuth, async (req, res) => {
  try {
    // If you have a courses model, create it here.
    res.json({ success: true });
  } catch(e){
    console.error("create course", e);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// complete lesson (public)
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ success:false, error: "Missing fields" });

    await Completion.updateOne(
      { user_id: userId, lesson_id: String(lessonId) },
      { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: String(lessonId) } },
      { upsert: true }
    );

    const totalLessons = Number(process.env.TOTAL_LESSONS) || 4;
    const done = await Completion.countDocuments({ user_id: userId });
    const percent = Math.round((done / totalLessons) * 100);
    await User.findByIdAndUpdate(userId, { percentage: percent });

    res.json({ success: true, percentage: percent });
  } catch (err) {
    console.error("Complete error:", err && err.message ? err.message : err);
    res.status(500).json({ success:false, error: "Server error" });
  }
});

// ---------- ROOT ----------
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send(`<h2>Backend running — put your LoginPage.html in /public</h2>`);
});

// ---------- GLOBAL ERROR HANDLING & GRACEFUL EXIT ----------
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
// End of server.js