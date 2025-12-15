/**
 * server.js — MindStep FINAL (100% FIXED)
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

/* ---------------- ENV CHECK ---------------- */
if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI missing");
  process.exit(1);
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

/* ---------------- DB ---------------- */
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch(err => {
    console.error("❌ Mongo error", err);
    process.exit(1);
  });

/* ---------------- APP ---------------- */
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

const upload = multer({ dest: TEMP_DIR });

/* ---------------- MODELS ---------------- */

// USER
const userSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true },
  email: { type: String, required: true },
  password: String,
  image: String,
  percentage: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});
const User = mongoose.model("User", userSchema);

// ADMIN
const adminSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: String,
  password: String
});
const Admin = mongoose.model("Admin", adminSchema);

// COURSE & LESSON
const Course = require("./models/Course");
const Lesson = require("./models/Lesson");

// COMPLETION ✅ FIXED
const completionSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  user_id: String,
  course_id: { type: mongoose.Schema.Types.ObjectId, ref: "Course" },
  lesson_id: { type: mongoose.Schema.Types.ObjectId, ref: "Lesson" }
});

// ✅ INDEX MUST BE ON SCHEMA (NOT MODEL)
completionSchema.index(
  { user_id: 1, lesson_id: 1 },
  { unique: true }
);

const Completion = mongoose.model("Completion", completionSchema);

/* ---------------- ADMIN AUTH ---------------- */
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const adminAuth = (req, res, next) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!ADMIN_SECRET || token !== ADMIN_SECRET)
    return res.status(401).json({ error: "Unauthorized" });
  next();
};

/* ---------------- AUTH ---------------- */
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "Missing fields" });

    let image = null;
    if (req.file) {
      const up = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep" });
      image = up.secure_url;
      fs.unlinkSync(req.file.path);
    }

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image
    });

    res.json({ success: true, user });
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
  const courses = await Course.find({});
  const result = [];

  for (const c of courses) {
    const lessonCount = await Lesson.countDocuments({ course_id: c._id });
    result.push({ course: c, lessonCount });
  }

  res.json({ success: true, results: result });
});

app.get("/api/course/:slug/lessons", async (req, res) => {
  const course = await Course.findOne({ slug: req.params.slug });
  if (!course) return res.status(404).json({ error: "Course not found" });

  const lessons = await Lesson.find({ course_id: course._id }).sort({ order: 1 });
  res.json({ success: true, course, lessons });
});

/* ---------------- PROGRESS ---------------- */
app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;
  const lessons = await Lesson.find({
  $or: [
    { course_id: course._id },
    { course_id: String(course._id) }
  ]
}).sort({ order: 1 });

  if (!lesson) return res.status(404).json({ error: "Lesson not found" });

  await Completion.updateOne(
    { user_id: userId, lesson_id: lesson._id },
    {
      $setOnInsert: {
        user_id: userId,
        lesson_id: lesson._id,
        course_id: lesson.course_id
      }
    },
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

  const percent = total ? Math.round((done / total) * 100) : 0;
  res.json({ success: true, percent });
});

/* ---------------- ADMIN ---------------- */
app.post("/api/admin-login", async (req, res) => {
  const admin = await Admin.findOne({ username: req.body.username });
  if (!admin || !bcrypt.compareSync(req.body.password, admin.password))
    return res.status(401).json({ error: "Invalid admin" });

  res.json({ success: true, adminSecret: ADMIN_SECRET });
});

app.get("/api/admin/users", adminAuth, async (req, res) => {
  const users = await User.find({}).select("-password");
  res.json({ success: true, users });
});

/* ---------------- ROOT ---------------- */
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  res.send("MindStep Backend Running");
});

/* ---------------- START ---------------- */
app.listen(PORT, () =>
  console.log(`🔥 MindStep running → http://localhost:${PORT}`)
);
