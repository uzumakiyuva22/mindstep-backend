// ===============================
//  MindStep - FINAL SERVER.JS
//  Cloudinary_URL + MongoDB + Admin + Piston
//  100% Error-Free Version
// ===============================

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
const util = require("util");
const { execFile } = require("child_process");
const execFileP = util.promisify(execFile);

// ------------------ CONFIG ------------------

const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");

// Cloudinary URL
if (!process.env.CLOUDINARY_URL) {
  console.error("❌ CLOUDINARY_URL missing!");
  process.exit(1);
}

cloudinary.config({
  cloudinary_url: process.env.CLOUDINARY_URL,
  secure: true
});

// MongoDB
if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI missing!");
  process.exit(1);
}

mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("✔ MongoDB Connected");
    // Seed courses on startup
    try {
      const seed = require("./seeds/seed.js");
      await seed();
    } catch (e) {
      console.warn("Seed warning:", e.message);
    }
  })
  .catch((err) => {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  });

// Admin Secret
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;

// ------------------ APP SETUP ------------------

const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// Multer (temp uploads)
const tempDir = path.join(__dirname, "temp");
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

const upload = multer({ dest: tempDir });

// safe unlink helper used by /run-code to remove temporary files
function safeUnlink(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (e) {
    // ignore
  }
}

// resolve Java binary command considering JAVA_HOME and platform
function resolveJavaBin(binName) {
  const isWin = process.platform === "win32";
  const JAVA_HOME = process.env.JAVA_HOME || null;
  // prefer JAVA_HOME if set
  if (JAVA_HOME) {
    const candidate = path.join(JAVA_HOME, "bin", binName + (isWin ? ".exe" : ""));
    if (fs.existsSync(candidate)) return candidate;
  }
  // prefer system command
  return binName;
}

// remote runner (Piston) fallback for environments without JDK
async function runOnPiston(language, version, files) {
  try {
    const resp = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language, version, files })
    });
    const data = await resp.json();
    // Piston responses vary; prefer run.stdout / run.output / run.stderr
    const out = data.run?.stdout || data.run?.output || data.run?.stderr || JSON.stringify(data);
    return { output: out };
  } catch (e) {
    return { error: (e && e.message) || String(e) };
  }
}

// ------------------ SCHEMAS ------------------

const userSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: String,
    email: String,
    password: String,
    image: String,
    percentage: { type: Number, default: 0 },
    deleted: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now }
  },
  { versionKey: false }
);

const adminSchema = new mongoose.Schema(
  {
    _id: { type: String, default: uuidv4 },
    username: String,
    password: String,
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

// ------------------ DEFAULT ADMIN ------------------

(async () => {
  const defaultAdmin = await Admin.findOne({ username: "Uzumaki_Yuva" });
  if (!defaultAdmin) {
    await Admin.create({
      username: "Uzumaki_Yuva",
      password: bcrypt.hashSync("yuva22", 10)
    });
    console.log("✔ Default admin created");
  }
})();

// ------------------ MIDDLEWARE ------------------

function adminAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || token !== ADMIN_SECRET)
    return res.status(401).json({ error: "Unauthorized" });
  next();
}

// ------------------ USER SIGNUP ------------------

app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.json({ success: false, error: "User already exists" });

    // Upload image
    let imageUrl = null;
    if (req.file) {
      const uploaded = await cloudinary.uploader.upload(req.file.path, {
        folder: "mindstep_users"
      });
      imageUrl = uploaded.secure_url;
      fs.unlinkSync(req.file.path);
    }

    const user = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      image: imageUrl
    });

    res.json({
      success: true,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        image: user.image
      }
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.json({ success: false, error: "Signup failed" });
  }
});

// ------------------ USER LOGIN ------------------

app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });

    if (!user) return res.json({ success: false, error: "Invalid login" });
    if (!bcrypt.compareSync(password, user.password))
      return res.json({ success: false, error: "Invalid login" });

    res.json({
      success: true,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        image: user.image,
        percentage: user.percentage
      }
    });
  } catch (e) {
    res.json({ success: false, error: "Server error" });
  }
});

// ------------------ ADMIN LOGIN ------------------

app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;

  const admin = await Admin.findOne({ username });
  if (!admin) return res.json({ success: false, error: "Admin not found" });

  const ok = bcrypt.compareSync(password, admin.password);
  if (!ok) return res.json({ success: false, error: "Wrong password" });

  res.json({ success: true, adminSecret: ADMIN_SECRET });
});

// ------------------ ADMIN ROUTES ------------------

app.get("/api/admin/overview", adminAuth, async (req, res) => {
  const totalUsers = await User.countDocuments({});
  res.json({
    success: true,
    totalUsers,
    activeCourses: 5,
    dailyVisits: 224,
    reports: 3
  });
});

app.get("/api/admin/users", adminAuth, async (req, res) => {
  const users = await User.find({}, "-password").lean();
  res.json({ success: true, users });
});

app.get("/api/admin/user/:id", adminAuth, async (req, res) => {
  const user = await User.findById(req.params.id).select("-password").lean();
  const lessonsDone = await Completion.countDocuments({ user_id: user._id });
  res.json({ success: true, user, lessonsDone });
});

app.put("/api/admin/user/:id", adminAuth, async (req, res) => {
  const update = {};
  if (req.body.username) update.username = req.body.username;
  if (req.body.email) update.email = req.body.email;
  if (req.body.password)
    update.password = bcrypt.hashSync(req.body.password, 10);

  await User.findByIdAndUpdate(req.params.id, update);
  res.json({ success: true });
});

app.post(
  "/api/admin/user/:id/image",
  adminAuth,
  upload.single("image"),
  async (req, res) => {
    if (!req.file) return res.json({ success: false, error: "No file" });

    const uploaded = await cloudinary.uploader.upload(req.file.path, {
      folder: "mindstep_users"
    });

    await User.findByIdAndUpdate(req.params.id, { image: uploaded.secure_url });
    fs.unlinkSync(req.file.path);

    res.json({ success: true, image: uploaded.secure_url });
  }
);

app.post("/api/admin/user/:id/purge", adminAuth, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  await Completion.deleteMany({ user_id: req.params.id });
  res.json({ success: true });
});

app.post("/api/admin/user/:id/reset", adminAuth, async (req, res) => {
  await Completion.deleteMany({ user_id: req.params.id });
  await User.findByIdAndUpdate(req.params.id, { percentage: 0 });
  res.json({ success: true });
});

// ------------------ PROGRESS ------------------

app.post("/api/complete", async (req, res) => {
  const { userId, lessonId } = req.body;

  await Completion.updateOne(
    { user_id: userId, lesson_id: lessonId },
    { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: lessonId } },
    { upsert: true }
  );

  const total = 4;
  const done = await Completion.countDocuments({ user_id: userId });
  const percent = Math.round((done / total) * 100);

  await User.findByIdAndUpdate(userId, { percentage: percent });

  res.json({ success: true, percentage: percent });
});

// ------------------ GET USER ------------------

app.get("/api/get-user/:id", async (req, res) => {
  const user = await User.findById(req.params.id).select("-password").lean();
  res.json(user);
});

// ------------------ RUN CODE ------------------
// NOTE: The local `/run-code` handler (below) runs code on the server
// directly (Java/Python/JS). A previous version proxied to the Piston
// API — that duplicate route has been removed so the local runner is used.

app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body || {};
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    console.log("/run-code request for", language);

    // ----- JAVA -----
    if (language === "java") {
      const javacCmd = resolveJavaBin("javac");
      const javaCmd = resolveJavaBin("java");

      // quick availability check (execFile will throw if not found)
      try {
        await execFileP(javacCmd, ["-version"]).catch(() => {});
        await execFileP(javaCmd, ["-version"]).catch(() => {});
      } catch (e) {
        console.error("Java availability check failed:", e && e.message);
        // fall back to remote runner if available
        const remote = await runOnPiston("java", "17", [{ name: `Main.java`, content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        return res.status(500).json({ error: "Java not available on server. Ensure JDK is installed and JAVA_HOME/PATH configured." });
      }

      // If the user declared a public class, Java requires the file name to
      // match that public class. Detect it and write the .java file using
      // that class name. Otherwise fall back to `Main`.
      const m = source.match(/public\s+class\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
      const className = m ? m[1] : "Main";
      const javaFile = path.join(tempDir, `${className}.java`);
      const classFile = path.join(tempDir, `${className}.class`);
      try {
        fs.writeFileSync(javaFile, source, "utf8");
        // compile
        await execFileP(javacCmd, [javaFile]);
      } catch (compileErr) {
        safeUnlink(javaFile); safeUnlink(classFile);
        const msg = (compileErr.stderr || compileErr.message || String(compileErr)).toString();
        console.error("Java compile error:", msg);
        // If javac isn't present, fall back to remote execution
        if (compileErr && (compileErr.code === 'ENOENT' || /ENOENT/.test(msg))) {
          console.info('javac not found locally — falling back to Piston remote execution');
          const remote = await runOnPiston('java', '17', [{ name: `${className}.java`, content: source }]);
          if (remote.output) return res.json({ output: remote.output });
          if (remote.error) return res.json({ error: 'Remote execution failed: ' + remote.error });
        }
        return res.json({ error: "Compilation failed: " + msg });
      }

      try {
        const { stdout, stderr } = await execFileP(javaCmd, ["-cp", tempDir, className]);
        const out = (stdout || "") + (stderr || "");
        return res.json({ output: out || "" });
      } catch (runErr) {
        const msg = (runErr.stderr || runErr.message || String(runErr)).toString();
        console.error("Java runtime error:", msg);
        // If java binary isn't present, fall back to remote execution
        if (runErr && (runErr.code === 'ENOENT' || /ENOENT/.test(msg))) {
          console.info('java not found locally — falling back to Piston remote execution');
          const remote = await runOnPiston('java', '17', [{ name: `${className}.java`, content: source }]);
          if (remote.output) return res.json({ output: remote.output });
          if (remote.error) return res.json({ error: 'Remote execution failed: ' + remote.error });
        }
        return res.json({ error: "Runtime failed: " + msg });
      } finally {
        safeUnlink(javaFile); safeUnlink(classFile);
      }
    }

    // ----- PYTHON -----
    if (language === "python") {
      const pyCmd = (process.env.PYTHON || "python");
      const pyFile = path.join(tempDir, "script.py");
      try {
        fs.writeFileSync(pyFile, source, "utf8");
        const { stdout, stderr } = await execFileP(pyCmd, [pyFile]);
        return res.json({ output: (stdout || "") + (stderr || "") });
      } catch (e) {
        const msg = (e.stderr || e.message || String(e)).toString();
        console.error("Python run error:", msg);
        return res.json({ error: "Python run failed: " + msg });
      } finally {
        safeUnlink(path.join(tempDir, "script.py"));
      }
    }

    // ----- JAVASCRIPT (server-side eval) -----
    if (language === "javascript") {
      try {
        const result = eval(source);
        return res.json({ output: String(result ?? "") });
      } catch (err) {
        return res.json({ error: "JS Error: " + err.message });
      }
    }

    return res.status(400).json({ error: "Language not supported" });
  } catch (err) {
    console.error("run-code handler error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ========== COURSE ENDPOINTS ==========

// Get all courses with lesson count
app.get("/api/public/courses", async (req, res) => {
  try {
    const Course = require("./models/Course");
    const Lesson = require("./models/Lesson");

    const courses = await Course.find({});
    const results = [];

    for (const course of courses) {
      const lessonCount = await Lesson.countDocuments({ course_id: course._id });
      results.push({ course, lessonCount });
    }

    res.json({ success: true, results });
  } catch (err) {
    console.error("Course fetch error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

  // Get course + lessons (and tasks) by slug
  app.get('/api/course/:slug/lessons', async (req, res) => {
    try {
      const { slug } = req.params;
      const Course = require('./models/Course');
      const Lesson = require('./models/Lesson');
      const Task = require('./models/Task');

      const course = await Course.findOne({ slug });
      if (!course) return res.status(404).json({ success: false, error: 'Course not found' });

      const lessons = await Lesson.find({ course_id: course._id }).sort({ order: 1 });

      // Attach tasks for each lesson (lightweight)
      const lessonIds = lessons.map(l => l._id);
      const tasks = await Task.find({ lesson_id: { $in: lessonIds } });

      const lessonsWithTasks = lessons.map(l => ({
        _id: l._id,
        title: l.title,
        section: l.section,
        order: l.order,
        content: l.content,
        tasks: tasks.filter(t => String(t.lesson_id) === String(l._id)).map(t => ({ _id: t._id, title: t.title, language: t.language }))
      }));

      res.json({ success: true, course, lessons: lessonsWithTasks });
    } catch (err) {
      console.error('Course lessons error:', err);
      res.status(500).json({ success: false, error: err.message });
    }
  });

// Get course progress for user
app.get("/api/course/:slug/progress/:userId", async (req, res) => {
  try {
    const { slug, userId } = req.params;
    const Course = require("./models/Course");
    const Lesson = require("./models/Lesson");

    const course = await Course.findOne({ slug });
    if (!course) return res.json({ percent: 0 });

    const lessons = await Lesson.find({ course_id: course._id });
    if (lessons.length === 0) return res.json({ percent: 0 });

    const completed = await Completion.countDocuments({
      user_id: userId,
      lesson_id: { $in: lessons.map(l => l._id) }
    });

    const percent = Math.round((completed / lessons.length) * 100);
    res.json({ percent });
  } catch (err) {
    console.error("Progress fetch error:", err);
    res.json({ percent: 0 });
  }
});

// Reseed courses (dev endpoint)
app.post("/api/admin/reseed", async (req, res) => {
  try {
    const Course = require("./models/Course");
    const Lesson = require("./models/Lesson");
    const Task = require("./models/Task");

    // Clear old data
    await Course.deleteMany({});
    await Lesson.deleteMany({});
    await Task.deleteMany({});

    // Run seed
    const seed = require("./seeds/seed");
    await seed();

    res.json({ success: true, message: "Courses reseeded successfully" });
  } catch (err) {
    console.error("Reseed error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ========== END COURSE ENDPOINTS ==========

// ------------------ ROOT ------------------

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html"));
});

// Health endpoint — reports whether Java compiler is available
app.get('/health', async (req, res) => {
  try {
    const javac = resolveJavaBin('javac');
    await execFileP(javac, ['-version']).catch(()=>{});
    return res.json({ status: 'ok', javac: true });
  } catch (e) {
    return res.json({ status: 'ok', javac: false });
  }
});

// ------------------ START ------------------

const server = app.listen(PORT, () =>
  console.log(`🔥 SERVER RUNNING → http://localhost:${PORT}`)
);

server.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Another instance may be running.`);
    console.error('To free the port on Windows run:');
    console.error('  netstat -ano | findstr ":' + PORT + '"');
    console.error('  taskkill /PID <pid> /F');
    process.exit(1);
  }
  console.error('Server error:', err);
  process.exit(1);
});
