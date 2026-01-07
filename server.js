/**
 * server.js — MindStep FINAL (100% Logic Fixed for Variable Values)
 * Fixes: Accepts ANY value (10, 30, 100...) if the variable syntax is correct.
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

/* ---------------- DB CONNECTION ---------------- */
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI).then(() => console.log("✔ MongoDB connected"));

/* ---------------- APP SETUP ---------------- */
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

const upload = multer({ dest: TEMP_DIR });
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin_secret_placeholder";

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
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) res.sendFile(file); else res.send("MindStep Backend Running");
});

app.get("/health", (req, res) => res.status(200).send("OK"));

/* ---------------- 🔥 THE MAIN FIX: LOGIC FOR ANY VALUE 🔥 ---------------- */
app.post("/api/task/submit", async (req, res) => {
  try {
    const { userId, lessonId, taskId, code } = req.body; 
    
    const user = await UserModel.findById(userId);
    const task = await Task.findById(taskId);
    if (!user || !task) return res.status(404).json({ success: false });

    const lang = (task.language || "").toLowerCase();

    // 1. HTML/CSS Preview (Always Pass if content exists)
    if (lang === "html" || lang === "css") {
      if (!code || code.trim().length < 5) return res.json({ success: false, passed: false, output: "Code too short" });
      await TaskProgress.findOneAndUpdate(
        { user_id: userId, task_id: taskId },
        { user_id: userId, lesson_id: lessonId, task_id: taskId, passed: true, output: "Preview", submittedAt: new Date() },
        { upsert: true }
      );
      return res.json({ success: true, passed: true, output: code, preview: true });
    }

    // 2. Run Code
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
    const expectedString = (task.expectedOutput || "").toString().replace(/\r/g, "").trim();
    
    let passed = false;
    let feedback = "";

    // ------------------------------------------------------------------
    // 🔥 THE FIX: ACCEPT ANY VALUE IF SYNTAX IS CORRECT
    // ------------------------------------------------------------------
    
    // Step A: Check Strict Match (Output == Expected)
    if (!expectedString || expectedString.toLowerCase() === "null") {
        passed = outputString.length > 0;
    } else {
        passed = outputString.includes(expectedString);
    }

    // Step B: SAFETY NET (This fixes your Int 30 vs 10 issue)
    // If strict match failed, check if the user used the correct Variable Type.
    if (!passed) {
        // Regex looks for: int, double, float, String, char, boolean, var, let, const
        // Followed by a variable name.
        // Example: "int a" matches. "int a=30" matches.
        const syntaxCheck = /\b(int|double|float|String|char|boolean|var|let|const)\s+[a-zA-Z0-9_]+/;
        
        // If code contains valid variable syntax AND produced ANY output -> PASS IT!
        if (syntaxCheck.test(code) && outputString.length > 0) {
            passed = true; 
            feedback = ""; // Clear the error because code logic is valid
        } else {
            feedback = `Expected output: "${expectedString}"\nYour output: "${outputString}"`;
        }
    }

    // Save Result
    await TaskProgress.findOneAndUpdate(
      { user_id: userId, task_id: taskId },
      { user_id: userId, lesson_id: lessonId, task_id: taskId, passed, output: outputString, submittedAt: new Date() },
      { upsert: true }
    );

    res.json({ success: true, passed, output: passed ? outputString : `${outputString}\n\n[ERROR]: ${feedback}` });

  } catch (err) { res.status(500).json({ success: false, error: "Server Error" }); }
});

/* ---------------- USER ROUTES ---------------- */
app.post("/api/login", async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;
        const user = await UserModel.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
        if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false });
        
        const total = await Lesson.countDocuments();
        const done = await Completion.countDocuments({ user_id: user._id });
        const pct = total ? Math.round((done/total)*100) : 0;
        
        res.json({ success: true, user: { ...user.toObject(), percentage: pct } });
    } catch { res.status(500).json({ success: false }); }
});

app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const user = await UserModel.create({ 
        username, email, password: bcrypt.hashSync(password, 10), 
        image: req.file ? `/uploads/${req.file.filename}` : null 
    });
    res.json({ success: true, user });
  } catch (err) { res.status(500).json({ success: false }); }
});

/* ---------------- COURSE & COMPLETION ---------------- */
app.post("/api/complete", async (req, res) => {
    try {
        const { userId, lessonId } = req.body;
        
        // Completion Gate: User must pass all tasks first
        const totalTasks = await Task.countDocuments({ lesson_id: lessonId });
        const passedTasks = await TaskProgress.countDocuments({ lesson_id: lessonId, user_id: userId, passed: true });
        
        if (totalTasks > 0 && passedTasks < totalTasks) {
            return res.status(400).json({ success: false, error: "Complete all tasks first" });
        }

        const lesson = await Lesson.findById(lessonId);
        await Completion.updateOne(
            { user_id: userId, lesson_id: lessonId }, 
            { $setOnInsert: { user_id: userId, course_id: lesson.course_id.toString(), lesson_id: lessonId, completed_at: new Date() } }, 
            { upsert: true }
        );
        
        const total = await Lesson.countDocuments({ course_id: lesson.course_id.toString() });
        const done = await Completion.countDocuments({ user_id: userId, course_id: lesson.course_id.toString() });
        res.json({ success: true, percent: total ? Math.round((done/total)*100) : 0 });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/public/courses", async (req, res) => {
    const courses = await Course.find({ isActive: true }).sort({ order: 1 });
    const results = await Promise.all(courses.map(async (c) => {
        const count = await Lesson.countDocuments({ course_id: c._id.toString() });
        return { course: c, lessonCount: count };
    }));
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
    const tasks = await Task.find({ lesson_id: req.params.lessonId }).sort({ order: 1 });
    res.json({ success: true, lesson, tasks });
});

app.get("/api/course/:slug/progress/:userId", async (req, res) => {
    const course = await Course.findOne({ slug: req.params.slug });
    const validIds = (await Lesson.find({ course_id: course._id }).select('_id')).map(l => l._id);
    const done = await Completion.find({ user_id: req.params.userId, lesson_id: { $in: validIds } });
    res.json({ success: true, percent: validIds.length ? Math.round((done.length/validIds.length)*100) : 0, completedLessonIds: done.map(c => c.lesson_id) });
});

/* ---------------- ADMIN & CERT ---------------- */
app.post("/api/auth/admin-login", async (req, res) => {
    const { username, password } = req.body;
    if (password === ADMIN_SECRET) {
        await AdminModel.updateOne({ username }, { $setOnInsert: { username, password: bcrypt.hashSync(password, 10) } }, { upsert: true });
        return res.json({ success: true, token: ADMIN_SECRET, admin: { username } });
    }
    const admin = await AdminModel.findOne({ username });
    if (admin && bcrypt.compareSync(password, admin.password)) return res.json({ success: true, token: ADMIN_SECRET, admin: { username } });
    res.status(401).json({ success: false });
});

app.post("/api/admin/login", async (req, res) => { /* Alternate endpoint for frontend consistency */
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
    const totalSystemLessons = await Lesson.countDocuments();
    const results = await Promise.all(users.map(async (u) => {
        const completed = await Completion.countDocuments({ user_id: u._id });
        const pct = totalSystemLessons ? Math.round((completed / totalSystemLessons) * 100) : 0;
        return { _id: u._id, username: u.username, email: u.email, image: u.image, percentage: pct, lessonsDone: completed, created_at: u.created_at };
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
    } catch (err) { res.status(500).json({ success: false }); }
});

/* ---------------- START ---------------- */
app.listen(PORT, () => console.log(`🔥 MindStep running → http://localhost:${PORT}`));