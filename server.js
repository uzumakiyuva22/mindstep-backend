// server.js — Fixed / Full-featured MindStep backend
// Node 18+ recommended (global fetch available)

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

// TEMP dir for compile/run
const tempDir = path.join(__dirname, "temp");
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

// ------------------ ENV / CLOUDINARY ------------------
// Cloudinary: prefer CLOUDINARY_URL (cloudinary://key:secret@name) or separate vars
if (!process.env.CLOUDINARY_URL && !(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET)) {
  console.error("❌ Cloudinary credentials missing. Set CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET");
  process.exit(1);
}
try {
  if (process.env.CLOUDINARY_URL) {
    cloudinary.config({ cloudinary_url: process.env.CLOUDINARY_URL, secure: true });
  } else {
    cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
      secure: true,
    });
  }
} catch (e) {
  console.error("❌ Cloudinary config error:", e && e.message ? e.message : e);
  process.exit(1);
}

// MongoDB
if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI missing!");
  process.exit(1);
}
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err && err.message ? err.message : err);
    process.exit(1);
  });

// Admin secret (must be set to use admin routes)
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;

// ------------------ APP SETUP ------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// Multer (temp uploads)
const upload = multer({ dest: tempDir, limits: { fileSize: 10 * 1024 * 1024 } });

// ------------------ HELPERS ------------------
function safeUnlink(fp) {
  try { if (fp && fs.existsSync(fp)) fs.unlinkSync(fp); } catch (e) {}
}

// Resolve java binary helper (used by run-code & health)
const isWin = process.platform === "win32";
const JAVA_HOME = process.env.JAVA_HOME || null;
function resolveJavaBin(binName) {
  if (JAVA_HOME) {
    const cand = path.join(JAVA_HOME, "bin", binName + (isWin ? ".exe" : ""));
    if (fs.existsSync(cand)) return cand;
  }
  // fallback to system path (let execFile throw if not found)
  return binName + (isWin ? ".exe" : "");
}

// Remote fallback runner (Piston)
async function runOnPiston(language, version, files) {
  try {
    const r = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language, version, files }),
    });
    const data = await r.json();
    const out = data.run?.stdout || data.run?.output || data.run?.stderr || JSON.stringify(data);
    return { output: out };
  } catch (e) {
    return { error: (e && e.message) || String(e) };
  }
}

// ------------------ MONGOOSE SCHEMAS ------------------
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

// ------------------ DEFAULT ADMIN ------------------
(async () => {
  try {
    const defaultAdminUser = "Uzumaki_Yuva";
    const found = await Admin.findOne({ username: defaultAdminUser }).lean();
    if (!found) {
      await Admin.create({ username: defaultAdminUser, password: bcrypt.hashSync("yuva22", 10) });
      console.log("✔ Default admin created (Uzumaki_Yuva)");
    } else {
      console.log("✔ Default admin exists");
    }
  } catch (e) {
    console.error("Admin init error:", e && e.message ? e.message : e);
  }
})();

// ------------------ MIDDLEWARE ------------------
function adminAuth(req, res, next) {
  if (!ADMIN_SECRET) return res.status(403).json({ error: "Admin routes disabled — set ADMIN_SECRET" });
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || token !== ADMIN_SECRET) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// ------------------ ROUTES ------------------

// HEALTH
app.get("/health", async (req, res) => {
  try {
    // check javac presence
    const javac = resolveJavaBin("javac");
    const java = resolveJavaBin("java");
    let javacOk = false;
    try {
      await execFileP(javac, ["-version"]).catch(()=>{});
      await execFileP(java, ["-version"]).catch(()=>{});
      javacOk = true;
    } catch (_) { javacOk = false; }
    res.json({ ok: true, javac: javacOk });
  } catch (e) {
    res.json({ ok: true, javac: false });
  }
});

// SIGNUP (image upload -> Cloudinary)
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success:false, error:"Missing fields" });

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
        safeUnlink(req.file.path);
      }
    }

    const user = await User.create({
      username, email,
      password: bcrypt.hashSync(password, 10),
      image: imageUrl
    });

    const out = { _id: user._id, username: user.username, email: user.email, image: user.image };
    res.json({ success: true, user: out });

  } catch (err) {
    console.error("Signup error:", err && err.message ? err.message : err);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ success:false, error:"Missing fields" });

    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }], deleted:false });
    if (!user) return res.status(401).json({ success:false, error:"Invalid login" });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success:false, error:"Invalid login" });

    const out = { _id: user._id, username: user.username, email: user.email, image: user.image, percentage: user.percentage };
    res.json({ success:true, user: out });
  } catch (e) {
    console.error("Login error:", e && e.message ? e.message : e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// ADMIN LOGIN — returns adminSecret for frontend to use (store carefully in render)
app.post("/api/admin-login", async (req, res) => {
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

// ADMIN OVERVIEW
app.get("/api/admin/overview", adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({});
    res.json({ success:true, totalUsers, activeCourses:5, dailyVisits:224, reports:3 });
  } catch (e) {
    console.error("/api/admin/overview error:", e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// LIST USERS
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, "-password").sort({ created_at: -1 }).lean();
    res.json({ success:true, users });
  } catch (e) {
    console.error("/api/admin/users error:", e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// GET single user
app.get("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const u = await User.findById(req.params.id).select("-password").lean();
    if (!u) return res.json({ success:false, error:"User not found" });
    const lessonsDone = await Completion.countDocuments({ user_id: u._id });
    res.json({ success:true, user:u, lessonsDone });
  } catch (e) {
    console.error("/api/admin/user/:id error:", e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// EDIT user
app.put("/api/admin/user/:id", adminAuth, async (req, res) => {
  try {
    const update = {};
    if (req.body.username) update.username = req.body.username;
    if (req.body.email) update.email = req.body.email;
    if (req.body.password) update.password = bcrypt.hashSync(req.body.password, 10);
    await User.findByIdAndUpdate(req.params.id, update);
    res.json({ success:true });
  } catch (e) {
    console.error("PUT /api/admin/user/:id error:", e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// ADMIN upload user image
app.post("/api/admin/user/:id/image", adminAuth, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success:false, error:"No file" });
    const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
    await User.findByIdAndUpdate(req.params.id, { image: uploaded.secure_url || uploaded.url || null });
    safeUnlink(req.file.path);
    res.json({ success:true, image: uploaded.secure_url || uploaded.url || null });
  } catch (e) {
    console.error("admin image upload error:", e && e.message ? e.message : e);
    safeUnlink(req.file && req.file.path);
    res.status(500).json({ success:false, error:"Upload failed" });
  }
});

// PURGE user
app.post("/api/admin/user/:id/purge", adminAuth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Completion.deleteMany({ user_id: req.params.id });
    res.json({ success:true });
  } catch (e) {
    console.error("Purge error:", e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// RESET progress
app.post("/api/admin/user/:id/reset", adminAuth, async (req, res) => {
  try {
    await Completion.deleteMany({ user_id: req.params.id });
    await User.findByIdAndUpdate(req.params.id, { percentage: 0 });
    res.json({ success:true });
  } catch (e) {
    console.error("Reset error:", e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// COMPLETE lesson (user)
app.post("/api/complete", async (req, res) => {
  try {
    const { userId, lessonId } = req.body;
    if (!userId || !lessonId) return res.status(400).json({ success:false, error:"Missing fields" });

    await Completion.updateOne(
      { user_id: userId, lesson_id: String(lessonId) },
      { $setOnInsert: { _id: uuidv4(), user_id: userId, lesson_id: String(lessonId) } },
      { upsert: true }
    );

    const totalLessons = 4; // adjust as needed
    const done = await Completion.countDocuments({ user_id: userId });
    const percent = Math.round((done / totalLessons) * 100);
    await User.findByIdAndUpdate(userId, { percentage: percent });

    res.json({ success:true, percentage: percent });
  } catch (e) {
    console.error("Complete error:", e);
    res.status(500).json({ success:false, error:"Server error" });
  }
});

// GET user (for frontend)
app.get("/api/get-user/:id", async (req, res) => {
  try {
    const u = await User.findById(req.params.id).select("-password").lean();
    if (!u) return res.status(404).json({ error: "User not found" });
    res.json(u);
  } catch (e) {
    console.error("/api/get-user error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------ RUN CODE (local runner with remote fallback) ------------------
app.post("/run-code", async (req, res) => {
  try {
    const { language, source } = req.body || {};
    if (!language || !source) return res.status(400).json({ error: "Missing language/source" });

    // ----- JAVA -----
    if (language === "java") {
      const javacCmd = resolveJavaBin("javac");
      const javaCmd = resolveJavaBin("java");

      // check availability
      let javacPresent = true;
      try {
        await execFileP(javacCmd, ["-version"]).catch(()=>{});
        await execFileP(javaCmd, ["-version"]).catch(()=>{});
      } catch (e) {
        javacPresent = false;
      }

      // Determine class name (if public class)
      const m = source.match(/public\s+class\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
      const className = m ? m[1] : "Main";
      const javaFile = path.join(tempDir, `${className}.java`);
      const classFile = path.join(tempDir, `${className}.class`);

      if (!javacPresent) {
        // fallback to remote execution
        const remote = await runOnPiston("java", "21", [{ name: `${className}.java`, content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        if (remote.error) return res.status(500).json({ error: "Remote execution failed: " + remote.error });
        return res.status(500).json({ error: "Java not available locally and remote failed." });
      }

      try {
        fs.writeFileSync(javaFile, source, "utf8");
        // compile
        await execFileP(javacCmd, [javaFile]);
      } catch (compileErr) {
        const msg = (compileErr.stderr || compileErr.message || String(compileErr)).toString();
        safeUnlink(javaFile); safeUnlink(classFile);
        console.error("Java compile error:", msg);
        // if javac missing, fallback (already attempted), otherwise return compile message
        return res.json({ error: "Compilation failed: " + msg });
      }

      try {
        const { stdout, stderr } = await execFileP(javaCmd, ["-cp", tempDir, className]);
        return res.json({ output: (stdout || "") + (stderr || "") });
      } catch (runErr) {
        const msg = (runErr.stderr || runErr.message || String(runErr)).toString();
        console.error("Java runtime error:", msg);
        // fallback remote
        const remote = await runOnPiston("java", "21", [{ name: `${className}.java`, content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        return res.json({ error: "Runtime failed: " + msg });
      } finally {
        safeUnlink(javaFile); safeUnlink(classFile);
      }
    }

    // ----- PYTHON -----
    if (language === "python") {
      const pyCmd = process.env.PYTHON || "python";
      const pyFile = path.join(tempDir, "script.py");
      try {
        fs.writeFileSync(pyFile, source, "utf8");
        const { stdout, stderr } = await execFileP(pyCmd, [pyFile]);
        return res.json({ output: (stdout || "") + (stderr || "") });
      } catch (e) {
        const msg = (e.stderr || e.message || String(e)).toString();
        console.error("Python run error:", msg);
        // remote fallback
        const remote = await runOnPiston("python", "3.10.0", [{ name: "script.py", content: source }]);
        if (remote.output) return res.json({ output: remote.output });
        return res.json({ error: "Python run failed: " + msg });
      } finally {
        safeUnlink(pyFile);
      }
    }

    // ----- JAVASCRIPT (eval) -----
    if (language === "javascript") {
      try {
        // sandbox note: this is not a secure sandbox — keep usage controlled
        const result = eval(source);
        return res.json({ output: String(result ?? "") });
      } catch (err) {
        return res.json({ error: "JS Error: " + (err && err.message ? err.message : String(err)) });
      }
    }

    return res.status(400).json({ error: "Language not supported" });
  } catch (err) {
    console.error("run-code handler error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ------------------ ROOT ------------------
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.send(`<h3>MindStep backend</h3><p>Put your frontend files inside /public</p>`);
});

// ------------------ START ------------------
const server = app.listen(PORT, () => console.log(`🔥 SERVER RUNNING → http://localhost:${PORT}`));
server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use.`);
    process.exit(1);
  }
  console.error("Server error:", err);
  process.exit(1);
});
