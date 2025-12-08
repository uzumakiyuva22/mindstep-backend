// server.js - Final (Cloudinary + MongoDB Atlas + Piston code runner)
// Node 18+ recommended

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

// If CLOUDINARY_URL starts with cloudinary:// use it, otherwise use parts
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
const upload = multer({ dest: tempDir });

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
    const a = await Admin.findOne({ username: "Uzumaki_Yuva" }).lean();
    if (!a) {
      await Admin.create({
        username: "Uzumaki_Yuza", // optionally change
        password: bcrypt.hashSync("yuva22", 10)
      });
      console.log("✔ Default admin created (username: Uzumaki_Yuza)");
    }
  } catch (e) { console.error("Admin init error:", e && e.message ? e.message : e); }
})();

// ---------- HEALTH ----------
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// ---------- SIGNUP (image -> Cloudinary) ----------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

    const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
    if (exists) return res.json({ error: "User already exists" });

    let imageUrl = null;
    if (req.file) {
      try {
        const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
        imageUrl = uploaded.secure_url || uploaded.url || null;
      } catch (upErr) {
        console.error("Cloudinary upload error:", upErr && upErr.message ? upErr.message : upErr);
        // continue without image if upload fails
      } finally {
        // remove temp file if exists
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
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Missing fields" });

    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }], deleted: false });
    if (!user) return res.json({ error: "Invalid Login" });

    if (!bcrypt.compareSync(password, user.password)) return res.json({ error: "Invalid Login" });

    const out = await User.findById(user._id).select("-password").lean();
    res.json({ success: true, user: out });
  } catch (err) {
    console.error("Login error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- ADMIN LOGIN ----------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if(!username||!password) return res.status(400).json({ error: "Missing fields" });

    const admin = await Admin.findOne({ username });
    if (!admin) return res.json({ error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password)) return res.json({ error: "Wrong password" });

    const out = await Admin.findById(admin._id).select("-password").lean();
    res.json({ success: true, admin: out });
  } catch (err) {
    console.error("Admin login error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- RUN CODE (Piston) ----------
// Node 18+ provides global fetch. No node-fetch required.
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    const map = {
      java: { language: "java", version: "17" },
      python: { language: "python", version: "3.10.0" },
      javascript: { language: "javascript", version: "18.15.0" }
    };
    if (!map[language]) return res.json({ error: "Language not supported" });

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
app.get("/user-info", adminAuth, async (req, res) => {
    try {
        const userId = req.user.id; // from JWT
        db.get(
            "SELECT id, username, email, image FROM users WHERE id = ?",
            [userId],
            (err, row) => {
                if (err) return res.status(500).json({ error: "DB error" });
                if (!row) return res.status(404).json({ error: "User not found" });

                res.json({
                    id: row.id,
                    username: row.username,
                    email: row.email,
                    image: row.image ? `/uploads/${row.image}` : "/default.png"
                });
            }
        );
    } catch (e) {
        res.status(500).json({ error: "Server error" });
    }
});
app.get("/all-users", adminAuth, (req, res) => {
    db.all(
        "SELECT id, username, email, percentage FROM users",
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: "DB error" });
            res.json(rows);
        }
    );
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

// ---------- ROOT ----------
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html")));

// ---------- START ----------
app.listen(PORT, () => console.log(`🔥 SERVER running at http://localhost:${PORT}`));
