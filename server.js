/**
 * server.js — MindStep backend
 * - Primary remote runner: JDoodle (recommended, stable for Java21)
 * - Fallback remote runner: Piston (if JDoodle not configured or fails)
 *
 * Required env:
 *  - MONGO_URI
 *  - CLOUDINARY_URL  OR (CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET)
 * Optional:
 *  - ADMIN_SECRET
 *  - JDOODLE_CLIENT_ID
 *  - JDOODLE_CLIENT_SECRET
 *  - JDOODLE_JAVA_VERSION_INDEX (string)
 *
 * Node 18+ recommended (fetch available)
 */

require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const cloudinary = require("cloudinary").v2;
const fetch = global.fetch || require("node-fetch"); // node 18 has fetch; fallback if not

// ------------- CONFIG -------------
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const TEMP_DIR = path.join(__dirname, "temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// ------------- ENV CHECKS -------------
if (!process.env.MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI missing in environment.");
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
  console.error("❌ ERROR: Cloudinary credentials missing. Set CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET");
  process.exit(1);
}

// Cloudinary config
try {
  if (process.env.CLOUDINARY_URL) cloudinary.config({ cloudinary_url: process.env.CLOUDINARY_URL, secure: true });
  else cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
} catch (e) {
  console.error("❌ Cloudinary config error:", e && e.message ? e.message : e);
  process.exit(1);
}

// JDoodle credentials (optional, preferred)
const JD_CLIENT_ID = process.env.JDOODLE_CLIENT_ID || null;
const JD_CLIENT_SECRET = process.env.JDOODLE_CLIENT_SECRET || null;
const JD_JAVA_VERSION_INDEX = process.env.JDOODLE_JAVA_VERSION_INDEX || ""; // optional string (e.g. "4") - if blank we try simple "java" call

// ------------- MONGODB -------------
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI)
  .then(()=>console.log("✔ MongoDB connected"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err && err.message ? err.message : err);
    process.exit(1);
  });

// ------------- EXPRESS -------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
const upload = multer({ dest: TEMP_DIR, limits: { fileSize: 10 * 1024 * 1024 } });

// ------------- HELPERS -------------
function safeUnlink(fp) {
  try { if (fp && fs.existsSync(fp)) fs.unlinkSync(fp); } catch(e) {}
}

// JDoodle runner
async function runOnJDoodle(language, versionIndex, script) {
  if (!JD_CLIENT_ID || !JD_CLIENT_SECRET) return { error: "JDoodle credentials not configured" };

  const payload = {
    clientId: JD_CLIENT_ID,
    clientSecret: JD_CLIENT_SECRET,
    script: script,
    language: language,
    versionIndex: typeof versionIndex === "string" && versionIndex.length > 0 ? versionIndex : "0"
  };

  try {
    const r = await fetch("https://api.jdoodle.com/v1/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    // JDoodle returns output or error fields
    if (data.output) return { output: data.output };
    if (data.error) return { error: data.error };
    // fallback: return whole JSON
    return { output: JSON.stringify(data) };
  } catch (e) {
    return { error: (e && e.message) || String(e) };
  }
}

// Piston fallback runner
async function runOnPiston(language, version, files) {
  try {
    const resp = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language, version, files })
    });
    const data = await resp.json();
    const out = data.run?.stdout || data.run?.output || data.run?.stderr || JSON.stringify(data);
    return { output: out };
  } catch (e) {
    return { error: (e && e.message) || String(e) };
  }
}

// ------------- SCHEMAS -------------
const userSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  image: { type: String, default: null },
  percentage: { type: Number, default: 0 },
  deleted: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
}, { versionKey: false });

const adminSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  created_at: { type: Date, default: Date.now }
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

// create default admin if missing
(async () => {
  try {
    const defaultAdmin = "Uzumaki_Yuva";
    const found = await Admin.findOne({ username: defaultAdmin }).lean();
    if (!found) {
      await Admin.create({ username: defaultAdmin, password: bcrypt.hashSync("yuva22", 10) });
      console.log("✔ Default admin created (Uzumaki_Yuva)");
    } else {
      console.log("✔ Default admin exists");
    }
  } catch (e) {
    console.error("Admin init error:", e && e.message ? e.message : e);
  }
})();

const ADMIN_SECRET = process.env.ADMIN_SECRET || null;
function adminAuth(req, res, next) {
  if (!ADMIN_SECRET) return res.status(403).json({ error: "Admin routes disabled (set ADMIN_SECRET)" });
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || token !== ADMIN_SECRET) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// ------------- ROUTES -------------
// Health
app.get("/health", (req,res) => res.json({ ok:true, ts: Date.now() }));

// Signup (image => Cloudinary)
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success:false, error:"Missing fields" });

    const exists = await User.findOne({ $or:[{username},{email}] }).lean();
    if (exists) return res.status(409).json({ success:false, error:"User exists" });

    let imageUrl = null;
    if (req.file) {
      try {
        const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
        imageUrl = uploaded.secure_url || uploaded.url || null;
      } catch (e) {
        console.error("Cloudinary upload error:", e && e.message ? e.message : e);
      } finally {
        safeUnlink(req.file.path);
      }
    }

    const user = await User.create({
      username, email,
      password: bcrypt.hashSync(password, 10),
      image: imageUrl
    });

    res.json({ success:true, user: { _id: user._id, username: user.username, email: user.email, image: user.image }});
  } catch (e) {
    console.error("Signup error:", e && e.message ? e.message : e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// Login
app.post("/api/login", async (req,res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ success:false, error:"Missing fields" });

    const user = await User.findOne({ $or:[{ username: usernameOrEmail }, { email: usernameOrEmail }], deleted:false });
    if (!user) return res.status(401).json({ success:false, error:"Invalid credentials" });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success:false, error:"Invalid credentials" });

    res.json({ success:true, user: { _id: user._id, username: user.username, email: user.email, image: user.image, percentage: user.percentage }});
  } catch (e) {
    console.error("Login error:", e && e.message ? e.message : e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// Admin login (returns adminSecret — store safely in frontend env)
app.post("/api/admin-login", async (req,res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success:false, error:"Missing fields" });
    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(404).json({ success:false, error:"Admin not found" });
    if (!bcrypt.compareSync(password, admin.password)) return res.status(401).json({ success:false, error:"Wrong password" });
    res.json({ success:true, admin: { id: admin._id, username: admin.username }, adminSecret: ADMIN_SECRET || null });
  } catch (e) {
    console.error("Admin login error:", e && e.message ? e.message : e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// Admin endpoints (list users, get user, edit user, upload user image, purge, reset)
app.get("/api/admin/users", adminAuth, async (req,res) => {
  try {
    const users = await User.find({}, "-password").sort({ created_at: -1 }).lean();
    res.json({ success:true, users });
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:"Server error" }); }
});

app.get("/api/admin/user/:id", adminAuth, async (req,res) => {
  try {
    const u = await User.findById(req.params.id).select("-password").lean();
    if (!u) return res.status(404).json({ success:false, error:"User not found" });
    const lessonsDone = await Completion.countDocuments({ user_id: u._id });
    res.json({ success:true, user: u, lessonsDone });
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:"Server error" }); }
});

app.put("/api/admin/user/:id", adminAuth, async (req,res) => {
  try {
    const update = {};
    if (req.body.username) update.username = req.body.username;
    if (req.body.email) update.email = req.body.email;
    if (req.body.password) update.password = bcrypt.hashSync(req.body.password, 10);
    await User.findByIdAndUpdate(req.params.id, update);
    res.json({ success:true });
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:"Server error" }); }
});

app.post("/api/admin/user/:id/image", adminAuth, upload.single("image"), async (req,res) => {
  try {
    if (!req.file) return res.status(400).json({ success:false, error:"No file" });
    const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
    const url = uploaded.secure_url || uploaded.url || null;
    await User.findByIdAndUpdate(req.params.id, { image: url });
    safeUnlink(req.file.path);
    res.json({ success:true, image: url });
  } catch (e) { console.error(e); safeUnlink(req.file && req.file.path); res.status(500).json({ success:false, error:"Upload failed" }); }
});

app.post("/api/admin/user/:id/purge", adminAuth, async (req,res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Completion.deleteMany({ user_id: req.params.id });
    res.json({ success:true });
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:"Server error" }); }
});

app.post("/api/admin/user/:id/reset", adminAuth, async (req,res) => {
  try {
    await Completion.deleteMany({ user_id: req.params.id });
    await User.findByIdAndUpdate(req.params.id, { percentage: 0 });
    res.json({ success:true });
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:"Server error" }); }
});

// Complete lesson endpoint
app.post("/api/complete", async (req,res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ success:false, error:"Missing fields" });
    await Completion.updateOne({ user_id: userId, lesson_id: String(lessonId) }, { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: String(lessonId) }}, { upsert:true });
    const totalLessons = 4;
    const done = await Completion.countDocuments({ user_id: userId });
    const percent = Math.round((done / totalLessons) * 100);
    await User.findByIdAndUpdate(userId, { percentage: percent });
    res.json({ success:true, percentage: percent });
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:"Server error" }); }
});

// Public: get user
app.get("/api/get-user/:id", async (req,res) => {
  try {
    const u = await User.findById(req.params.id).select("-password").lean();
    if (!u) return res.status(404).json({ error:"User not found" });
    res.json(u);
  } catch (e) { console.error(e); res.status(500).json({ error:"Server error" }); }
});

// ------------- RUN CODE (JDoodle preferred, fallback to Piston) -------------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body || {};
    if (!language || !source) return res.status(400).json({ error: "Missing language or source" });

    // Always try JDoodle first if credentials exist
    if (JD_CLIENT_ID && JD_CLIENT_SECRET) {
      if (language === "java") {
        // JDoodle: language "java" - versionIndex must be provided; if not, JDoodle API may accept "0" or a default
        const jv = JD_JAVA_VERSION_INDEX && JD_JAVA_VERSION_INDEX.length > 0 ? JD_JAVA_VERSION_INDEX : "0";
        const runResult = await runOnJDoodle("java", jv, source);
        if (runResult.output) return res.json({ output: runResult.output });
        if (runResult.error) {
          // If JDoodle responds with error, log and fallback to Piston
          console.warn("JDoodle Java error:", runResult.error);
          // fallback to piston
          const remote = await runOnPiston("java", "21", [{ name: "Main.java", content: source }]);
          if (remote.output) return res.json({ output: remote.output });
          return res.status(500).json({ error: "Unknown Java remote error", detail: runResult.error });
        }
      }

      if (language === "python") {
        const runResult = await runOnJDoodle("python3", "3", source); // JDoodle usually uses "python3"
        if (runResult.output) return res.json({ output: runResult.output });
        if (runResult.error) {
          console.warn("JDoodle Python error:", runResult.error);
          const remote = await runOnPiston("python", "3.10.0", [{ name: "script.py", content: source }]);
          if (remote.output) return res.json({ output: remote.output });
          return res.status(500).json({ error: "Unknown Python remote error", detail: runResult.error });
        }
      }

      if (language === "javascript") {
        const runResult = await runOnJDoodle("nodejs", "node-18", source);
        if (runResult.output) return res.json({ output: runResult.output });
        if (runResult.error) {
          console.warn("JDoodle JS error:", runResult.error);
          const remote = await runOnPiston("javascript", "18.15.0", [{ name: "script.js", content: source }]);
          if (remote.output) return res.json({ output: remote.output });
          return res.status(500).json({ error: "Unknown JS remote error", detail: runResult.error });
        }
      }
    }

    // If JDoodle not configured, use Piston (best-effort)
    if (!JD_CLIENT_ID || !JD_CLIENT_SECRET) {
      // Piston expects language and version
      if (language === "java") {
        const remote = await runOnPiston("java", "21", [{ name: "Main.java", content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        return res.status(500).json({ error: "Unknown Java remote error" });
      }
      if (language === "python") {
        const remote = await runOnPiston("python", "3.10.0", [{ name: "script.py", content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        return res.status(500).json({ error: "Unknown Python remote error" });
      }
      if (language === "javascript") {
        const remote = await runOnPiston("javascript", "18.15.0", [{ name: "script.js", content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        return res.status(500).json({ error: "Unknown JS remote error" });
      }
    }

    return res.status(400).json({ error: "Language not supported" });
  } catch (err) {
    console.error("run-code handler error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "Server error" });
  }
});

// Root
app.get("/", (req,res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send("<h3>MindStep backend</h3><p>Place frontend files in /public</p>");
});

// Start
const server = app.listen(PORT, () => console.log(`🔥 Server listening on http://localhost:${PORT}`));
server.on("error", (err) => {
  console.error("Server error:", err && err.message ? err.message : err);
  process.exit(1);
});
