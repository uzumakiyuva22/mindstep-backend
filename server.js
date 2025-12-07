// =======================================
// FINAL SERVER.JS (CLOUDINARY + MONGODB)
// =======================================

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const fetch = require("node-fetch");

// ⚡ Cloudinary Setup
const cloudinary = require("cloudinary").v2;
cloudinary.config({
  cloudinary_url: process.env.CLOUDINARY_URL,
});

// CONFIG
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const MONGO_URI = process.env.MONGO_URI;

// Validate Mongo URI
if (!MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI missing in environment variables!");
  process.exit(1);
}

// Ensure public folder exists
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

// Connect Mongoose
mongoose.set("strictQuery", false);
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ======================================
// SCHEMAS
// ======================================

const userSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: String,
    image: { type: String, default: null }, // Cloudinary URL
    percentage: { type: Number, default: 0 },
    deleted: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now }
  },
  { versionKey: false }
);

const adminSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: { type: String, unique: true },
    password: String,
    display_name: String,
    created_at: { type: Date, default: Date.now }
  },
  { versionKey: false }
);

const completionSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    user_id: String,
    lesson_id: String
  },
  { versionKey: false }
);

completionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });

const User = mongoose.model("User", userSchema);
const Admin = mongoose.model("Admin", adminSchema);
const Completion = mongoose.model("Completion", completionSchema);

// ======================================
// Create Default Admin
// ======================================

(async () => {
  const existing = await Admin.findOne({ username: "Uzumaki_Yuva" });
  if (!existing) {
    await Admin.create({
      username: "Uzumaki_Yuva",
      password: bcrypt.hashSync("yuva22", 10),
      display_name: "MindStep Administrator"
    });
    console.log("✔ Default Admin Created!");
  }
})();

// ======================================
// EXPRESS SETUP
// ======================================

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Serve frontend
app.use(express.static(PUBLIC_DIR));

// Multer memory storage (for Cloudinary)
const upload = multer({ storage: multer.memoryStorage() });

// ======================================
// HEALTH CHECK
// ======================================

app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// ======================================
// SIGNUP (with Cloudinary Image Upload)
// ======================================

app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
      return res.json({ error: "Missing fields" });

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.json({ error: "User already exists" });

    let imageURL = null;

    if (req.file) {
      const uploadRes = await cloudinary.uploader.upload_stream(
        { folder: "mindstep_users" },
        (error, result) => {
          if (error) console.log("Cloudinary Error:", error);
        }
      );
    }

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image: imageURL
    });

    res.json({ success: true, user });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ======================================
// LOGIN
// ======================================

app.post("/api/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  const user = await User.findOne({
    $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
  });

  if (!user) return res.json({ error: "Invalid login" });
  if (!bcrypt.compareSync(password, user.password))
    return res.json({ error: "Invalid login" });

  res.json({ success: true, user });
});

// ======================================
// ADMIN LOGIN
// ======================================

app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;

  const admin = await Admin.findOne({ username });
  if (!admin) return res.json({ error: "Admin not found" });

  if (!bcrypt.compareSync(password, admin.password))
    return res.json({ error: "Wrong password" });

  res.json({ success: true, admin });
});

// ======================================
// ADMIN — ALL USERS
// ======================================

app.get("/api/admin/users", async (req, res) => {
  const users = await User.find({ deleted: false }).lean();
  res.json({ success: true, users });
});

// ======================================
// COMPLETE LESSON
// ======================================

app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;

  await Completion.updateOne(
    { user_id: userId, lesson_id: lessonId },
    { $setOnInsert: { _id: uuidv4() } },
    { upsert: true }
  );

  const totalLessons = 4;
  const done = await Completion.countDocuments({ user_id: userId });

  const percent = Math.round((done / totalLessons) * 100);
  await User.findByIdAndUpdate(userId, { percentage: percent });

  res.json({ success: true, percentage: percent });
});

// ======================================
// RUN CODE (Java 17 Fixed)
// ======================================

app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;

    const PISTON = "https://emkc.org/api/v2/piston/execute";

    const payload = {
      java: { language: "java", version: "17.0.3" },
      python: { language: "python", version: "3.10.0" },
      javascript: { language: "js", version: "1.32.0" }
    };

    if (!payload[language])
      return res.json({ error: "Language not supported" });

    const result = await fetch(PISTON, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...payload[language],
        files: [{ name: "Main", content: source }]
      })
    });

    const data = await result.json();
    res.json({ output: data.run?.output || JSON.stringify(data) });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ======================================
// ROOT SERVE LOGIN PAGE
// ======================================

app.get("/", (req, res) =>
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"))
);

// ======================================
// START SERVER
// ======================================

app.listen(PORT, () =>
  console.log(`🔥 SERVER LIVE at PORT ${PORT}`)
);
