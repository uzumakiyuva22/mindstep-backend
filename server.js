/**
 * server.js — MindStep FINAL (Concept-Based Validation Logic)
 * Features:
 * 1. Checks CONCEPT (int, double, string) instead of strict values.
 * 2. Allows ANY value (10, 42, 99.9) as long as the variable type is correct.
 * 3. Enforces HTML tags (<button>, <h1>) if required.
 * 4. Secure Admin & Lesson Logic.
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

/* ---------------- UTILS ---------------- */
const runJava = require("./utils/runJava");
const runPython = require("./utils/runPython");
const runJavaScript = require("./utils/runJavaScript");
const generateCertificate = require("./utils/generateCertificate");
const sendCertificateMail = require("./utils/sendCertificateMail");

/* ---------------- CONFIG ---------------- */
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const TEMP_DIR = path.join(__dirname, "temp");

if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

/* ---------------- ENV CHECKS ---------------- */
if (!process.env.MONGO_URI) { console.error("❌ MONGO_URI missing"); process.exit(1); }
if (!process.env.ADMIN_SECRET) { console.error("❌ ADMIN_SECRET missing"); process.exit(1); }
const ADMIN_SECRET = process.env.ADMIN_SECRET;

/* ---------------- DB CONNECTION ---------------- */
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI).then(() => console.log("✔ MongoDB connected"));

/* ---------------- CLOUDINARY ---------------- */
const CLOUDINARY_ENABLED = Boolean(process.env.CLOUDINARY_CLOUD_NAME);
if (CLOUDINARY_ENABLED) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
}

/* ---------------- APP SETUP ---------------- */
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
const upload = multer({ dest: TEMP_DIR });

/* ---------------- MODELS ---------------- */
const userSchema = new mongoose.Schema({ _id: { type: String, default: uuidv4 }, username: String, email: { type: String, unique: true }, password: String, image: String, created_at: { type: Date, default: Date.now } });
const UserModel = mongoose.models.User || mongoose.model("User", userSchema);

const adminSchema = new mongoose.Schema({ _id: { type: String, default: uuidv4 }, username: String, password: String });
const AdminModel = mongoose.models.Admin || mongoose.model("Admin", adminSchema);

const taskProgressSchema = new mongoose.Schema({ user_id: String, lesson_id: mongoose.Schema.Types.ObjectId, task_id: mongoose.Schema.Types.ObjectId, passed: Boolean, output: String, submittedAt: Date });
taskProgressSchema.index({ user_id: 1, task_id: 1 }, { unique: true });
const TaskProgress = mongoose.models.TaskProgress || mongoose.model("TaskProgress", taskProgressSchema);

const completionSchema = new mongoose.Schema({ user_id: String, course_id: String, lesson_id: mongoose.Schema.Types.ObjectId, completed_at: Date });
completionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });
const Completion = mongoose.models.Completion || mongoose.model("Completion", completionSchema);

const Task = require("./models/Task");
const Course = require("./models/Course");
const Lesson = require("./models/Lesson");

// Middleware
function requireAdminMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (!token || token !== ADMIN_SECRET) return res.status(401).json({ success: false });
  next();
}

/* ---------------- ROUTES ---------------- */
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "AdminDashboard.html")));
app.get("/admin/login", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "AdminLogin.html")));
app.get("/health", (req, res) => res.status(200).send("OK"));

/* ---------------- 🔥 SMART CONCEPT VALIDATION (THE FIX) 🔥 ---------------- */
app.post("/api/task/submit", async (req, res) => {
  try {
    const { userId, lessonId, taskId, code } = req.body;
    
    if (!mongoose.Types.ObjectId.isValid(lessonId) || !mongoose.Types.ObjectId.isValid(taskId)) {
        return res.status(400).json({ success: false, error: "Invalid ID format" });
    }
    const lessonObjectId = new mongoose.Types.ObjectId(lessonId);

    const user = await UserModel.findById(userId);
    const task = await Task.findById(taskId);
    if (!user || !task) return res.status(404).json({ success: false, error: "Not Found" });

    // Ensure Task belongs to Lesson
    if (task.lesson_id.toString() !== lessonId) {
        return res.status(403).json({ success: false, error: "Task mismatches lesson." });
    }

    const lang = (task.language || "").toLowerCase();
    
    // --- 1. HTML & CSS Validation ---
    if (lang === "html" || lang === "css") {
        if (!code || code.trim().length < 5) return res.json({ success: false, passed: false, output: "Code too short" });
        
        let webPassed = true;
        let webFeedback = "";

        // Check for specific tags/properties defined in DB validation rule
        // If DB has "mustContain": "button", check for <button
        const required = task.validation?.mustContain || "";
        
        if (required) {
            if (lang === 'html') {
                const tagRegex = new RegExp(`<${required}\\b`, "i");
                if (!tagRegex.test(code)) {
                    webPassed = false;
                    webFeedback = `Missing required tag: <${required}>`;
                }
            } else {
                if (!code.includes(required)) {
                    webPassed = false;
                    webFeedback = `Missing required CSS property: '${required}'`;
                }
            }
        }

        await TaskProgress.findOneAndUpdate(
            { user_id: userId, task_id: taskId },
            { user_id: userId, lesson_id: lessonObjectId, task_id: taskId, passed: webPassed, output: "Preview", submittedAt: new Date() },
            { upsert: true }
        );
        
        return res.json({ 
            success: true, 
            passed: webPassed, 
            output: webPassed ? code : `[ERROR]: ${webFeedback}`, 
            preview: true 
        });
    }

    // --- 2. Code Execution ---
    let result;
    try {
      if (lang === "java") result = await runJava(code);
      else if (lang === "python") result = await runPython(code);
      else if (lang === "javascript") result = await runJavaScript(code);
      else return res.json({ success: false, passed: false, error: "Unsupported Language" });
    } catch (runErr) { 
        return res.json({ success: false, passed: false, output: "Runtime Error: " + runErr.message }); 
    }

    const outputString = result?.output?.toString().replace(/\r/g, "").trim() || "";
    
    // -------------------------------------------------------------
    // 🔥 CONCEPT VALIDATION LOGIC (INTELLIGENT CHECK)
    // -------------------------------------------------------------
    let passed = true;
    let feedback = "";
    
    // We check the "concept" field in the DB (schema based) OR infer from title (fallback)
    const rule = task.validation || {}; 
    const concept = rule.concept || (task.title.toLowerCase().includes("integer") ? "integer" : 
                                     task.title.toLowerCase().includes("decimal") ? "decimal" : 
                                     task.title.toLowerCase().includes("string") ? "string" : "generic");

    // --- JAVA RULES ---
    if (lang === "java") {
        if (concept === "integer") {
            // Must have 'int'
            if (!code.match(/\bint\s+/)) {
                passed = false;
                feedback = "Incorrect Logic: You must declare an 'int' variable.";
            } else if (code.match(/\bdouble\s+/)) {
                passed = false;
                feedback = "Incorrect Logic: Do not use 'double' for integers.";
            }
        }
        else if (concept === "decimal") {
            // Must have 'double' or 'float'
            if (!code.match(/\b(double|float)\s+/)) {
                passed = false;
                feedback = "Incorrect Logic: You must declare a 'double' or 'float' variable.";
            }
        }
        else if (concept === "string") {
            // Must have 'String'
            if (!code.match(/\bString\s+/)) {
                passed = false;
                feedback = "Incorrect Logic: You must declare a 'String' variable.";
            }
        }
    }

    // --- PYTHON RULES ---
    if (lang === "python") {
        if (concept === "decimal") {
            // Python needs assignment like x = 10.5
            if (!code.match(/=\s*\d+\.\d+/)) {
                passed = false;
                feedback = "Incorrect Logic: You must assign a decimal value (e.g., 10.5).";
            }
        }
    }

    // --- JAVASCRIPT RULES ---
    if (lang === "javascript") {
        if (concept === "decimal" && !code.match(/=\s*\d+\.\d+/)) {
            passed = false; 
            feedback = "Incorrect Logic: You must store a decimal number.";
        }
    }

    // --- FINAL DECISION ---
    if (passed) {
        // If concept is correct, check output presence
        if (outputString.length > 0) {
            passed = true; // SUCCESS! Value doesn't matter (10 or 42 is fine)
            feedback = "";
        } else {
            passed = false;
            feedback = "Logic correct, but nothing was printed to the output.";
        }
    }

    // Save Result
    await TaskProgress.findOneAndUpdate(
      { user_id: userId, task_id: taskId },
      { 
          user_id: userId, 
          lesson_id: lessonObjectId, 
          task_id: taskId, 
          passed, 
          output: passed ? outputString : "", 
          submittedAt: new Date() 
      },
      { upsert: true }
    );

    res.json({ success: true, passed, output: passed ? outputString : `${outputString}\n\n[ERROR]: ${feedback}` });

  } catch (err) { console.error(err); res.status(500).json({ success: false, error: "Server Error" }); }
});

/* ---------------- USER & COMPLETION ROUTES ---------------- */
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    let image = null;
    if (req.file) {
      if (CLOUDINARY_ENABLED) {
        const result = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep/users" });
        image = result.secure_url;
      } else {
        const targetPath = path.join(UPLOADS_DIR, req.file.filename + path.extname(req.file.originalname));
        fs.renameSync(req.file.path, targetPath);
        image = `/uploads/${path.basename(targetPath)}`;
      }
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    }
    const user = await UserModel.create({ username, email, password: bcrypt.hashSync(password, 10), image });
    res.json({ success: true, user });
  } catch (err) { res.status(500).json({ success: false }); }
});

app.post("/api/login", async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;
        const user = await UserModel.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
        if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false });
        const total = await Lesson.countDocuments();
        const done = await Completion.countDocuments({ user_id: user._id });
        res.json({ success: true, user: { ...user.toObject(), percentage: total ? Math.round((done/total)*100) : 0 } });
    } catch { res.status(500).json({ success: false }); }
});

app.post("/api/complete", async (req, res) => {
    try {
        const { userId, lessonId } = req.body;
        const lessonObjectId = new mongoose.Types.ObjectId(lessonId);
        
        const totalTasks = await Task.countDocuments({ lesson_id: lessonObjectId });
        const passedTasks = await TaskProgress.countDocuments({ lesson_id: lessonObjectId, user_id: userId, passed: true });
        
        if (totalTasks > 0 && passedTasks < totalTasks) return res.status(400).json({ success: false, error: "Complete all tasks first" });

        const lesson = await Lesson.findById(lessonId);
        await Completion.updateOne(
            { user_id: userId, lesson_id: lessonObjectId }, 
            { $setOnInsert: { user_id: userId, course_id: lesson.course_id.toString(), lesson_id: lessonObjectId, completed_at: new Date() } }, 
            { upsert: true }
        );
        const total = await Lesson.countDocuments({ course_id: lesson.course_id.toString() });
        const done = await Completion.countDocuments({ user_id: userId, course_id: lesson.course_id.toString() });
        res.json({ success: true, percent: total ? Math.round((done/total)*100) : 0 });
    } catch { res.status(500).json({ success: false }); }
});

// Getters
app.get("/api/public/courses", async (req, res) => {
    const courses = await Course.find({ isActive: true }).sort({ order: 1 });
    const results = await Promise.all(courses.map(async (c) => ({ course: c, lessonCount: await Lesson.countDocuments({ course_id: c._id.toString() }) })));
    res.json({ success: true, results });
});
app.get("/api/course/:slug", async (req, res) => {
    const course = await Course.findOne({ slug: req.params.slug });
    res.json({ success: true, course });
});
app.get("/api/course/:slug/lessons", async (req, res) => {
    const course = await Course.findOne({ slug: req.params.slug });
    const lessons = await Lesson.find({ course_id: course._id }).sort({ order: 1 });
    res.json({ success: true, lessons });
});
app.get("/api/lesson/:lessonId/details", async (req, res) => {
    const lesson = await Lesson.findById(req.params.lessonId).lean();
    const tasks = await Task.find({ lesson_id: new mongoose.Types.ObjectId(req.params.lessonId) }).sort({ order: 1 });
    res.json({ success: true, lesson, tasks });
});
app.get("/api/course/:slug/progress/:userId", async (req, res) => {
    const course = await Course.findOne({ slug: req.params.slug });
    const validIds = (await Lesson.find({ course_id: course._id }).select('_id')).map(l => l._id);
    const done = await Completion.find({ user_id: req.params.userId, lesson_id: { $in: validIds } });
    res.json({ success: true, percent: validIds.length ? Math.round((done.length/validIds.length)*100) : 0, completedLessonIds: done.map(c => c.lesson_id) });
});

/* ---------------- ADMIN ---------------- */
app.post("/api/admin/login", async (req, res) => {
    const { username, password } = req.body;
    if (password === ADMIN_SECRET) {
        await AdminModel.updateOne({ username }, { $setOnInsert: { username, password: bcrypt.hashSync(password, 10) } }, { upsert: true });
        return res.json({ success: true, token: ADMIN_SECRET, admin: { username } });
    }
    const admin = await AdminModel.findOne({ username });
    if (admin && bcrypt.compareSync(password, admin.password)) return res.json({ success: true, token: ADMIN_SECRET, admin: { username } });
    res.status(401).json({ success: false });
});

app.get("/api/admin/overview", requireAdminMiddleware, async (req, res) => {
    const totalUsers = await UserModel.countDocuments();
    const activeCourses = await Course.countDocuments();
    res.json({ success: true, totalUsers, activeCourses });
});

app.get("/api/admin/users", requireAdminMiddleware, async (req, res) => {
    const users = await UserModel.find({}).lean();
    const total = await Lesson.countDocuments();
    const results = await Promise.all(users.map(async (u) => {
        const done = await Completion.countDocuments({ user_id: u._id });
        return { _id: u._id, username: u.username, email: u.email, image: u.image, percentage: total ? Math.round((done/total)*100) : 0, created_at: u.created_at };
    }));
    res.json({ success: true, users: results });
});

app.post("/api/admin/user/:id/reset", requireAdminMiddleware, async (req, res) => {
    const id = req.params.id;
    await Completion.deleteMany({ user_id: id });
    await TaskProgress.deleteMany({ user_id: id });
    res.json({ success: true });
});

app.post("/api/admin/user/:id/purge", requireAdminMiddleware, async (req, res) => {
    const id = req.params.id;
    await UserModel.deleteOne({ _id: id });
    await Completion.deleteMany({ user_id: id });
    await TaskProgress.deleteMany({ user_id: id });
    res.json({ success: true });
});

app.post("/api/generate-certificate", async (req, res) => {
    try {
        const { userId, courseTitle } = req.body;
        const user = await UserModel.findById(userId);
        if (!user) return res.status(404).json({ success: false });
        const certificateId = `MS-${Date.now()}`;
        const pdfPath = await generateCertificate({ username: user.username, courseTitle, certificateId });
        await sendCertificateMail({ to: user.email, username: user.username, courseTitle, attachmentPath: pdfPath });
        res.json({ success: true, message: "Sent" });
    } catch { res.status(500).json({ success: false }); }
});

app.listen(PORT, () => console.log(`🔥 MindStep running → http://localhost:${PORT}`));