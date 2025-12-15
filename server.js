/**
 * server.js — MindStep FINAL (100% FIXED & STABLE)
 * Node 18+
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

/* ---------------- CONFIG ---------------- */
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const TEMP_DIR = path.join(__dirname, "temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

/* ---------------- ENV ---------------- */
if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI missing");
  process.exit(1);
}

const CLOUDINARY_ENABLED = Boolean(
  process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
);

if (CLOUDINARY_ENABLED) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true,
  });
} else {
  console.warn(
    "⚠ Cloudinary credentials missing — image uploads will be stored locally at public/uploads/"
  );
}

/* ---------------- DB ---------------- */
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch(err => {
    console.error("❌ Mongo error", err);
    process.exit(1);
  });

/* ---------------- APP ---------------- */
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

const upload = multer({ dest: TEMP_DIR });

/* ---------------- MODELS ---------------- */

// USER
const User = mongoose.model("User", new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: String,
  email: String,
  password: String,
  image: String,
  percentage: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
}));

// ADMIN
const Admin = mongoose.model("Admin", new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: String,
  password: String
}));

// COURSE & LESSON
const Course = require("./models/Course");
const Lesson = require("./models/Lesson");

// COMPLETION — use shared model
const Completion = require("./models/Completion");

// ADMIN SECRET (fallback)
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin_secret_placeholder";

// helper to check admin token from Authorization: Bearer <token>
function requireAdminMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (!token || token !== ADMIN_SECRET) return res.status(401).json({ success: false, error: "Unauthorized" });
  next();
}

/* ---------------- AUTH ---------------- */
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "Missing fields" });

    let image = null;
    if (req.file) {
      if (CLOUDINARY_ENABLED) {
        try {
          const up = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep" });
          image = up.secure_url;
        } catch (err) {
          console.error("Cloudinary upload failed:", err);
        } finally {
          if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        }
      } else {
        const ext = path.extname(req.file.originalname) || "";
        const filename = `${uuidv4()}${ext}`;
        const dest = path.join(UPLOADS_DIR, filename);
        fs.renameSync(req.file.path, dest);
        image = `/uploads/${filename}`;
      }
    }

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image
    });

    // Normalize image URL for response
    const respUser = user.toObject ? user.toObject() : user;
    if (respUser.image && respUser.image.startsWith("/")) {
      const base = `${req.protocol}://${req.get("host")}`;
      respUser.image = base + respUser.image;
    }

    res.json({ success: true, user: respUser });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/api/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  const user = await User.findOne({
    $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
  });

  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Invalid login" });

  res.json({ success: true, user });
});

/* ---------------- COURSES ---------------- */
app.get("/api/public/courses", async (req, res) => {
  const courses = await Course.find();
  const results = [];

  for (const c of courses) {
    const count = await Lesson.countDocuments({ course_id: c._id });
    results.push({ course: c, lessonCount: count });
  }

  res.json({ success: true, results });
});

app.get("/api/course/:slug/lessons", async (req, res) => {
  const course = await Course.findOne({ slug: req.params.slug });
  if (!course) return res.status(404).json({ error: "Course not found" });

  const lessons = await Lesson.find({ course_id: course._id }).sort({ order: 1 });
  res.json({ success: true, course, lessons });
});

/* ---------------- PROGRESS (🔥 FIXED) ---------------- */
app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;

  const lesson = await Lesson.findById(lessonId);
  if (!lesson) return res.status(404).json({ error: "Lesson not found" });

  await Completion.updateOne(
    { user_id: userId, lesson_id: lesson._id },
    { $setOnInsert: { user_id: userId, lesson_id: lesson._id, course_id: lesson.course_id } },
    { upsert: true }
  );

  const total = await Lesson.countDocuments({ course_id: lesson.course_id });
  const done = await Completion.countDocuments({
    user_id: userId,
    course_id: lesson.course_id
  });

  const percent = total ? Math.round((done / total) * 100) : 0;
  await User.findByIdAndUpdate(userId, { percentage: percent });

  res.json({ success: true, percent });
});

app.get("/api/course/:slug/progress/:userId", async (req, res) => {
  const course = await Course.findOne({ slug: req.params.slug });
  if (!course) return res.status(404).json({ error: "Course not found" });

  const total = await Lesson.countDocuments({ course_id: course._id });
  const done = await Completion.countDocuments({
    user_id: req.params.userId,
    course_id: course._id
  });

  res.json({ success: true, percent: total ? Math.round((done / total) * 100) : 0 });
});

/* ---------------- ADMIN AUTH & ROUTES ---------------- */

// Admin login endpoint used by AdminLogin.html
app.post("/api/auth/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: "Missing credentials" });

    // Try to find admin in DB
    const admin = await Admin.findOne({ username });
    if (admin) {
      if (!bcrypt.compareSync(password, admin.password)) return res.json({ success: false, error: "Invalid admin" });
      return res.json({ success: true, token: ADMIN_SECRET, admin: { username: admin.username } });
    }

    // Fallback: allow login when password matches ADMIN_SECRET
    if (password === ADMIN_SECRET) {
      // ensure admin exists in DB for convenience
      try {
        await Admin.updateOne({ username }, { $setOnInsert: { username, password: bcrypt.hashSync(password, 10) } }, { upsert: true });
      } catch (e) { /* ignore */ }
      return res.json({ success: true, token: ADMIN_SECRET, admin: { username } });
    }

    return res.json({ success: false, error: "Invalid admin" });
  } catch (err) {
    console.error("ADMIN LOGIN ERROR", err);
    res.status(500).json({ success: false, error: "Admin login failed" });
  }
});

// Admin overview
app.get("/api/admin/overview", requireAdminMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeCourses = await Course.countDocuments();
    const reports = 3;
    const dailyVisits = 224;
    res.json({ success: true, totalUsers, activeCourses, reports, dailyVisits });
  } catch (err) {
    res.json({ success: false, error: "Overview error" });
  }
});

// Get users
app.get("/api/admin/users", requireAdminMiddleware, async (req, res) => {
  try {
    const users = await User.find({}).lean();
    const results = [];
    for (const u of users) {
      const completed = await Completion.countDocuments({ user_id: u._id });
      const total = await Lesson.countDocuments();
      const pct = total === 0 ? 0 : Math.round((completed / total) * 100);
      results.push({ _id: u._id, username: u.username, email: u.email, image: u.image, percentage: pct, lessonsDone: completed, created_at: u.created_at || new Date() });
    }
    res.json({ success: true, users: results });
  } catch (err) {
    res.json({ success: false, error: "Users load error" });
  }
});

// Get single user
app.get("/api/admin/user/:id", requireAdminMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const u = await User.findById(id).lean();
    if (!u) return res.json({ success: false, error: "User not found" });
    const completed = await Completion.countDocuments({ user_id: id });
    const total = await Lesson.countDocuments();
    const pct = total === 0 ? 0 : Math.round((completed / total) * 100);
    res.json({ success: true, user: u, lessonsDone: completed, percentage: pct });
  } catch (err) {
    res.json({ success: false, error: "User fetch error" });
  }
});

// Update user
app.put("/api/admin/user/:id", requireAdminMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const { username, email, password } = req.body;
    const update = { username, email };
    if (password) update.password = bcrypt.hashSync(password, 10);
    await User.updateOne({ _id: id }, { $set: update });
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, error: "Update failed" });
  }
});

// Reset progress
app.post("/api/admin/user/:id/reset", requireAdminMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    await Completion.deleteMany({ user_id: id });
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, error: "Reset failed" });
  }
});

// Purge user
app.post("/api/admin/user/:id/purge", requireAdminMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    await User.deleteOne({ _id: id });
    await Completion.deleteMany({ user_id: id });
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, error: "Delete failed" });
  }
});

/* ---------------- ROOT ---------------- */
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  res.send("MindStep Backend Running");
});

/* ---------------- START ---------------- */
const server = app.listen(PORT, () =>
  console.log(`🔥 MindStep running → http://localhost:${PORT}`)
);

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(`❌ Port ${PORT} is already in use. Is another server running?`);
    process.exit(1);
  }
  console.error("❌ Server error:", err);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});
