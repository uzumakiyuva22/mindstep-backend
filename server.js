// server.js

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

if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI missing");
  process.exit(1);
}
if (!process.env.CLOUDINARY_URL) {
  console.error("❌ CLOUDINARY_URL missing");
  process.exit(1);
}

// ---------- CLOUDINARY ----------
const cloudinary = require("cloudinary").v2;
cloudinary.config({
  secure: true
});

// ---------- EXPRESS ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------- MULTER TEMP UPLOAD ----------
const upload = multer({ dest: "temp/" });

// ---------- DATABASE ----------
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

// ---------- SCHEMAS ----------
const userSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: String,
    email: String,
    password: String,
    image: String,
    percentage: { type: Number, default: 0 },
    deleted: { type: Boolean, default: false }
  },
  { versionKey: false }
);

const adminSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: String,
    password: String
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

// ---------- DEFAULT ADMIN ----------
(async () => {
  const admin = await Admin.findOne({ username: "Uzumaki_Yuva" });
  if (!admin) {
    await Admin.create({
      username: "Uzumaki_Yuva",
      password: bcrypt.hashSync("yuva22", 10)
    });
    console.log("✔ Default Admin Created");
  }
})();

// ---------- HEALTH ----------
app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- SIGNUP ----------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.json({ error: "User already exists" });

    let imgUrl = null;
    if (req.file) {
      const img = await cloudinary.uploader.upload(req.file.path, {
        folder: "mindstep_users"
      });
      imgUrl = img.secure_url;
      fs.unlinkSync(req.file.path);
    }

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image: imgUrl
    });

    const out = await User.findById(user._id).select("-password");
    res.json({ success: true, user: out });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
      deleted: false
    });

    if (!user) return res.json({ error: "Invalid login" });

    if (!bcrypt.compareSync(password, user.password))
      return res.json({ error: "Invalid login" });

    const out = await User.findById(user._id).select("-password");
    res.json({ success: true, user: out });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ---------- RUN CODE (PISTON API) ----------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;

    const config = {
      java: { language: "java", version: "17" },
      python: { language: "python", version: "3.10.0" },
      javascript: { language: "javascript", version: "18.15.0" }
    };

    if (!config[language])
      return res.json({ error: "Language not supported" });

    const pistonRes = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...config[language],
        files: [{ name: "Main", content: source }]
      })
    });

    const data = await pistonRes.json();
    res.json({ output: data.run?.output || "" });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ---------- COMPLETE LESSON ----------
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;

    await Completion.updateOne(
      { user_id: userId, lesson_id: lessonId },
      { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: lessonId } },
      { upsert: true }
    );

    const done = await Completion.countDocuments({ user_id: userId });
    const total = 4;
    const percent = Math.round((done / total) * 100);

    await User.findByIdAndUpdate(userId, { percentage: percent });

    res.json({ success: true, percentage: percent });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ---------- ROOT ----------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// ---------- START SERVER ----------
app.listen(PORT, () =>
  console.log(`🔥 SERVER LIVE on port ${PORT}`)
);
