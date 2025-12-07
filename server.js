// server.js
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

// CONFIG
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
const MONGO_URI = process.env.MONGO_URI || "";

if (!MONGO_URI) {
  console.error("ERROR: set MONGO_URI in env (see README / Render env vars). Exiting.");
  process.exit(1);
}

// ensure folders exist
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Mongoose connection (no deprecated options)
mongoose.set("strictQuery", false);
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err && err.message ? err.message : err);
    process.exit(1);
  });

// SCHEMAS & MODELS
const userSchema = new mongoose.Schema({
  _id: { type: String, default: () => uuidv4() },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  image: { type: String, default: null },
  percentage: { type: Number, default: 0 },
  deleted: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now },
}, { versionKey: false });

const adminSchema = new mongoose.Schema({
  _id: { type: String, default: () => uuidv4() },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  display_name: { type: String, default: "Admin" },
  created_at: { type: Date, default: Date.now },
}, { versionKey: false });

const completionSchema = new mongoose.Schema({
  _id: { type: String, default: () => uuidv4() },
  user_id: { type: String, required: true },
  lesson_id: { type: String, required: true },
}, { versionKey: false });
completionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });

const courseSchema = new mongoose.Schema({
  _id: { type: String, default: () => uuidv4() },
  title: String,
  description: String,
  created_at: { type: Date, default: Date.now },
}, { versionKey: false });

const User = mongoose.model("User", userSchema);
const Admin = mongoose.model("Admin", adminSchema);
const Completion = mongoose.model("Completion", completionSchema);
const Course = mongoose.model("Course", courseSchema);

// Ensure default admin exists
(async function ensureAdmin(){
  try {
    const a = await Admin.findOne({ username: "Uzumaki_Yuva" }).lean();
    if (!a) {
      await Admin.create({
        username: "Uzumaki_Yuva",
        password: bcrypt.hashSync("yuva22", 10),
        display_name: "MindStep Administrator"
      });
      console.log("✔ Default admin created: Uzumaki_Yuva / yuva22");
    }
  } catch(e) {
    console.error("Admin creation error:", e && e.message ? e.message : e);
  }
})();

// EXPRESS
const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));

// multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// helper
function handleServerError(res, err) {
  console.error(err && err.message ? err.message : err);
  return res.status(500).json({ error: "Server error" });
}

// ---------- HEALTH ----------
app.get("/health", (req,res) => res.json({ ok: true, ts: Date.now() }));

// ---------- AUTH: signup / login ----------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

    const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
    if (exists) return res.json({ error: "User already exists" });

    const img = req.file ? "/uploads/" + req.file.filename : null;
    const u = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image: img
    });
    const out = await User.findById(u._id).select("-password").lean();
    res.json({ success: true, user: out });
  } catch (err) { return handleServerError(res, err); }
});

app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Missing fields" });

    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }], deleted: false });
    if (!user) return res.json({ error: "Invalid Login" });

    if (!bcrypt.compareSync(password, user.password)) return res.json({ error: "Invalid Login" });

    const out = await User.findById(user._id).select("-password").lean();
    res.json({ success: true, user: out });
  } catch (err) { return handleServerError(res, err); }
});

// ---------- ADMIN ----------
app.post("/api/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({ error: "Missing fields" });

    const admin = await Admin.findOne({ username });
    if (!admin) return res.json({ error: "Admin not found" });

    if (!bcrypt.compareSync(password, admin.password)) return res.json({ error: "Wrong password" });

    const out = await Admin.findById(admin._id).select("-password").lean();
    res.json({ success: true, admin: out });
  } catch (err) { return handleServerError(res, err); }
});

app.get("/api/admin/users", async (req, res) => {
  try {
    const users = await User.find({ deleted: false }).select("-password").sort({ created_at: -1 }).lean();
    res.json({ success: true, users });
  } catch (err) { return handleServerError(res, err); }
});

app.get("/api/admin/overview", async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({ deleted: false });
    const totalCompletions = await Completion.countDocuments();
    const courseCount = await Course.countDocuments();
    const avgObj = await User.aggregate([
      { $match: { deleted: false } },
      { $group: { _id: null, avg: { $avg: "$percentage" } } }
    ]);
    const avg = Math.round((avgObj[0]?.avg || 0));
    res.json({ success: true, totalUsers, activeCourses: courseCount, totalCompletions, averageProgress: avg });
  } catch (err) { return handleServerError(res, err); }
});

app.get("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findById(id).select("-password").lean();
    if (!user) return res.json({ success: false, error: "User not found" });
    const lessonsDone = await Completion.countDocuments({ user_id: id });
    res.json({ success: true, user, lessonsDone });
  } catch (err) { return handleServerError(res, err); }
});

app.get("/api/admin/user/:id/lessons", async (req,res) => {
  try {
    const id = req.params.id;
    const c = await Completion.countDocuments({ user_id: id });
    res.json({ success: true, count: c });
  } catch(err) { return handleServerError(res, err); }
});

app.post("/api/admin/user/:id/soft-delete", async (req, res) => {
  try { await User.findByIdAndUpdate(req.params.id, { deleted: true }); res.json({ success: true }); }
  catch (err) { return handleServerError(res, err); }
});

app.post("/api/admin/user/:id/restore", async (req, res) => {
  try { await User.findByIdAndUpdate(req.params.id, { deleted: false }); res.json({ success: true }); }
  catch (err) { return handleServerError(res, err); }
});

app.post("/api/admin/user/:id/purge", async (req, res) => {
  try {
    const id = req.params.id;
    const force = req.body.force === true || req.body.force === "true";
    if (!force) return res.json({ success: false, error: "Force flag required" });

    await Completion.deleteMany({ user_id: id });
    await User.findByIdAndDelete(id);
    res.json({ success: true });
  } catch (err) { return handleServerError(res, err); }
});

app.put("/api/admin/user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const { username, email, password } = req.body;
    const other = await User.findOne({ $or: [{ username }, { email }], _id: { $ne: id } }).lean();
    if (other) return res.json({ success: false, error: "Username or email used" });

    const update = { username, email };
    if (password && password.length) update.password = bcrypt.hashSync(password, 10);
    await User.findByIdAndUpdate(id, update);
    res.json({ success: true });
  } catch (err) { return handleServerError(res, err); }
});

app.post("/api/admin/user/:id/image", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, error: "No file uploaded" });
    const imagePath = "/uploads/" + req.file.filename;
    await User.findByIdAndUpdate(req.params.id, { image: imagePath });
    res.json({ success: true, image: imagePath });
  } catch (err) { return handleServerError(res, err); }
});

// ---------- COMPLETIONS / PROGRESS ----------
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
  } catch (err) { return handleServerError(res, err); }
});

// ---------- RUN CODE (online Piston) ----------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    const PISTON = "https://emkc.org/api/v2/piston/execute";

    if (language === "java") {
      const r = await fetch(PISTON, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: "java",
          version: "17",
          files: [{ name: "Main.java", content: source }],
        }),
      });
      const d = await r.json();
      return res.json({ output: d.run?.output || JSON.stringify(d) });
    }

    if (language === "python") {
      const r = await fetch(PISTON, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: "python",
          version: "3.10.0",
          files: [{ name: "main.py", content: source }],
        }),
      });
      const d = await r.json();
      return res.json({ output: d.run?.output || JSON.stringify(d) });
    }

    if (language === "javascript") {
      try { const out = eval(source); return res.json({ output: String(out ?? "") }); }
      catch (e) { return res.json({ error: "JS Error: " + e.message }); }
    }

    return res.json({ error: "Language not supported" });
  } catch (err) { return handleServerError(res, err); }
});

// ---------- COURSE / PROGRESS APIS ----------
app.post("/get-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await User.findOne({ username, deleted: false }).lean();
    if (!user) return res.json({ success: false, error: "User not found" });

    const c = await Completion.countDocuments({ user_id: user._id });
    res.json({ success: true, percentage: user.percentage, lessonsCompleted: c });
  } catch (err) { return handleServerError(res, err); }
});

app.post("/save-progress", async (req, res) => {
  try {
    const { username, percentage, lessons_completed } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await User.findOne({ username, deleted: false }).lean();
    if (!user) return res.json({ success: false, error: "User not found" });

    const n = Math.max(0, Number(lessons_completed || 0));
    for (let i = 1; i <= n; i++) {
      await Completion.updateOne({ user_id: user._id, lesson_id: String(i) },
        { $setOnInsert: { _id: uuidv4(), user_id: user._id, lesson_id: String(i) } }, { upsert: true });
    }

    const pct = Math.max(0, Math.min(100, Number(percentage || 0)));
    await User.findByIdAndUpdate(user._id, { percentage: pct });
    res.json({ success: true, percentage: pct, lessons_completed: n });
  } catch (err) { return handleServerError(res, err); }
});

app.post("/update-main-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await User.findOne({ username, deleted: false }).lean();
    if (!user) return res.json({ success: false, error: "User not found" });

    const done = await Completion.countDocuments({ user_id: user._id });
    const totalLessons = 4;
    const percent = Math.round((done / totalLessons) * 100);
    await User.findByIdAndUpdate(user._id, { percentage: percent });
    res.json({ success: true, percentage: percent });
  } catch (err) { return handleServerError(res, err); }
});

app.post("/get-main-progress", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const user = await User.findOne({ username, deleted: false }).lean();
    return res.json({ success: true, fullStack: (user ? user.percentage : 0) || 0 });
  } catch (err) { return handleServerError(res, err); }
});

app.get("/progress", async (req, res) => {
  try {
    const usersCount = await User.countDocuments({ deleted: false });
    const totalCompletions = await Completion.countDocuments();
    const avgObj = await User.aggregate([{ $match: { deleted: false } }, { $group: { _id: null, avg: { $avg: "$percentage" } } }]);
    const avgPct = Math.round(avgObj[0]?.avg || 0);
    res.json({ percentage: avgPct, completed: totalCompletions, users: usersCount });
  } catch (err) { return handleServerError(res, err); }
});

// root - serve login page by default
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html")));

// fallback for unknown POST routes to keep JSON responses consistent
app.use((req, res, next) => {
  if (req.method === "POST") return res.status(404).json({ error: "Endpoint not found" });
  next();
});

// start
app.listen(PORT, () => console.log(`🔥 SERVER running at http://localhost:${PORT}`));
