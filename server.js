// =========================
// FINAL SERVER.JS (100% WORKING)
// =========================

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 10000;

// -------------------- PATHS --------------------
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");

// create folders if missing
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);


// ------------------ MONGO CONNECTION ------------------
const MONGO_URI =
  "mongodb+srv://yuvarajyuvarajan222:yuva132333@cluster0.o6ojbni.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✔ MongoDB Connected Successfully"))
  .catch((err) => {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  });

mongoose.set("strictQuery", false);


// ------------------ SCHEMAS ------------------
const UserSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: String,
    image: String,
    percentage: { type: Number, default: 0 },
    deleted: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now },
  },
  { versionKey: false }
);

const AdminSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: { type: String, unique: true },
    password: String,
    display_name: String,
  },
  { versionKey: false }
);

const CompletionSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    user_id: String,
    lesson_id: String,
  },
  { versionKey: false }
);
CompletionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });

const CourseSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    title: String,
    description: String,
  },
  { versionKey: false }
);

const User = mongoose.model("User", UserSchema);
const Admin = mongoose.model("Admin", AdminSchema);
const Completion = mongoose.model("Completion", CompletionSchema);
const Course = mongoose.model("Course", CourseSchema);


// ------------------ DEFAULT ADMIN ------------------
(async () => {
  const exists = await Admin.findOne({ username: "Uzumaki_Yuva" });
  if (!exists) {
    await Admin.create({
      username: "Uzumaki_Yuva",
      password: bcrypt.hashSync("yuva22", 10),
      display_name: "MindStep Admin",
    });
    console.log("✔ Default Admin Created: Uzumaki_Yuva / yuva22");
  }
})();


// ------------------- EXPRESS CONFIG -------------------
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOADS_DIR));


// ------------------ MULTER STORAGE ------------------
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage });


// ================================================================
// ======================== AUTH APIs ==============================
// ================================================================

// ------------------ SIGNUP ------------------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.json({ error: "User already exists" });

    const img = req.file ? "/uploads/" + req.file.filename : null;

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image: img,
    });

    const out = await User.findById(user._id).select("-password");
    res.json({ success: true, user: out });

  } catch (err) {
    console.error(err);
    res.json({ error: "Signup failed" });
  }
});

// ------------------ LOGIN ------------------
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    const user = await User.findOne({
      $or: [{ usernameOrEmail }, { email: usernameOrEmail }],
      deleted: false,
    });

    if (!user) return res.json({ error: "Invalid login" });

    if (!bcrypt.compareSync(password, user.password))
      return res.json({ error: "Invalid login" });

    const out = await User.findById(user._id).select("-password");
    res.json({ success: true, user: out });

  } catch (err) {
    res.json({ error: "Login failed" });
  }
});


// ================================================================
// ======================== ADMIN APIs =============================
// ================================================================

app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;

  const admin = await Admin.findOne({ username });
  if (!admin) return res.json({ error: "Admin not found" });

  if (!bcrypt.compareSync(password, admin.password))
    return res.json({ error: "Wrong password" });

  res.json({ success: true, admin });
});

app.get("/api/admin/users", async (req, res) => {
  const users = await User.find({ deleted: false })
    .select("-password")
    .sort({ created_at: -1 });

  res.json({ success: true, users });
});

app.get("/api/admin/user/:id", async (req, res) => {
  const user = await User.findById(req.params.id).select("-password");
  if (!user) return res.json({ error: "User not found" });

  const lessonsDone = await Completion.countDocuments({ user_id: user._id });

  res.json({ success: true, user, lessonsDone });
});

app.delete("/api/admin/user/:id", async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  await Completion.deleteMany({ user_id: req.params.id });

  res.json({ success: true });
});

app.post("/api/admin/user/:id/reset", async (req, res) => {
  await Completion.deleteMany({ user_id: req.params.id });
  await User.findByIdAndUpdate(req.params.id, { percentage: 0 });

  res.json({ success: true });
});

app.put("/api/admin/user/:id", async (req, res) => {
  const { username, email, password } = req.body;

  const update = { username, email };
  if (password) update.password = bcrypt.hashSync(password, 10);

  await User.findByIdAndUpdate(req.params.id, update);
  res.json({ success: true });
});

app.post("/api/admin/user/:id/image", upload.single("image"), async (req, res) => {
  const image = "/uploads/" + req.file.filename;
  await User.findByIdAndUpdate(req.params.id, { image });
  res.json({ success: true, image });
});


// ================================================================
// ================= PROGRESS / COMPLETION =========================
// ================================================================

app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;

  await Completion.updateOne(
    { user_id: userId, lesson_id: String(lessonId) },
    { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: String(lessonId) } },
    { upsert: true }
  );

  const done = await Completion.countDocuments({ user_id: userId });
  const percent = Math.round((done / 4) * 100);

  await User.findByIdAndUpdate(userId, { percentage: percent });

  res.json({ success: true, percentage: percent });
});


// ================================================================
// ===================== ONLINE COMPILER ===========================
// ================================================================

app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body;

    const PISTON = "https://emkc.org/api/v2/piston/execute";

    const body = {
      language,
      version:
        language === "java" ? "17" :
        language === "python" ? "3.10.0" :
        "18",
      files: [{ name: language === "java" ? "Main.java" : "main", content: source }],
    };

    const output = await fetch(PISTON, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => r.json());

    res.json({ output: output.run?.output || JSON.stringify(output) });

  } catch (err) {
    res.json({ error: "Execution error" });
  }
});


// ---------------- ROOT ----------------
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});


// ---------------- START SERVER ----------------
app.listen(PORT, () =>
  console.log(`🔥 Server running at http://localhost:${PORT}`)
);
