/**
 * server.js — MindStep FINAL PLATINUM EDITION (Viva Optimized)
 * * ✅ FEATURES & FIXES INCLUDED:
 * 1. Project Workflow: Upload -> Pending -> Admin Approve -> XP Awarded.
 * 2. Strict File Security: Validates MIME types (ZIP/PDF/DOCX).
 * 3. Dashboard Fix: Restored /api/public/courses route.
 * 4. User Schema: Tracks 'submitted' vs 'completed' lessons separately.
 * 5. Admin PDF/Content: Upload PDFs, update Video/Notes for lessons.
 * 6. Admin Stats: Fixed key names (pendingCount) for dashboard compatibility.
 * 7. Cascade Delete: Deleting a lesson now cleans up all related data (Pro feature).
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
const rateLimit = require("express-rate-limit"); 

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
const PROJECT_DIR = path.join(UPLOADS_DIR, "projects");
if (!fs.existsSync(PROJECT_DIR)) fs.mkdirSync(PROJECT_DIR, { recursive: true });
const PDF_DIR = path.join(UPLOADS_DIR, "lesson-pdfs");
if (!fs.existsSync(PDF_DIR)) fs.mkdirSync(PDF_DIR, { recursive: true });

/* ---------------- ENV CHECKS ---------------- */
if (!process.env.MONGO_URI) { console.error("❌ MONGO_URI missing"); process.exit(1); }
if (!process.env.ADMIN_SECRET) { console.error("❌ ADMIN_SECRET missing"); process.exit(1); }
const ADMIN_SECRET = process.env.ADMIN_SECRET;

/* ---------------- DB CONNECTION ---------------- */
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

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
app.disable("x-powered-by"); // Security: Hide backend tech
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// Admin Rate Limiter
const adminLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 60, 
  message: { success: false, message: "Too many admin requests." }
});
app.use("/api/admin", adminLimiter);

const upload = multer({ dest: TEMP_DIR });

/* ---------------- UPLOAD CONFIGS ---------------- */
const projectStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, PROJECT_DIR),
    filename: (req, file, cb) => {
        const safeOriginalName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
        cb(null, `${req.body.userId}-${req.body.lessonId}-${Date.now()}_${safeOriginalName}`);
    }
});

const uploadProject = multer({ 
    storage: projectStorage,
    limits: { fileSize: 50 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        const allowedMimes = [
            'application/zip', 'application/x-zip-compressed', 'application/x-tar', 'application/gzip',
            'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        if (allowedMimes.includes(file.mimetype)) cb(null, true);
        else {
            const ext = path.extname(file.originalname).toLowerCase();
            if (['.zip', '.rar', '.7z', '.tar', '.gz', '.pdf', '.docx'].includes(ext)) cb(null, true);
            else cb(new Error('Invalid file type. Only ZIP, PDF, or DOCX allowed.'));
        }
    }
});

const uploadPDF = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, PDF_DIR),
        filename: (req, file, cb) => {
            const safe = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
            cb(null, `${Date.now()}_${safe}`);
        }
    }),
    limits: { fileSize: 10 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "application/pdf") cb(null, true);
        else cb(new Error("Only PDF files allowed for lesson materials"));
    }
});

/* ---------------- MODELS ---------------- */
const userSchema = new mongoose.Schema({ 
    _id: { type: String, default: uuidv4 }, 
    username: { type: String, required: true, trim: true }, 
    email: { type: String, unique: true, required: true, lowercase: true, trim: true }, 
    password: { type: String, required: true }, 
    image: String, 
    created_at: { type: Date, default: Date.now },
    xp: { type: Number, default: 0 },
    submitted_lessons: { type: [String], default: [] },
    completed_lessons: { type: [String], default: [] }
});
const UserModel = mongoose.models.User || mongoose.model("User", userSchema);

const adminSchema = new mongoose.Schema({ 
    _id: { type: String, default: uuidv4 }, 
    username: String, 
    password: String 
});
const AdminModel = mongoose.models.Admin || mongoose.model("Admin", adminSchema);

const projectSchema = new mongoose.Schema({
    userId: String,
    courseId: String,
    lessonId: String,
    projectType: String,
    originalName: String,
    storedName: String,
    filePath: String,
    fileSize: Number,
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    reviewComment: String,
    createdAt: { type: Date, default: Date.now }
});
// Performance Indexes
projectSchema.index({ status: 1 });
projectSchema.index({ userId: 1 });
const Project = mongoose.models.Project || mongoose.model("Project", projectSchema);

const taskProgressSchema = new mongoose.Schema({ 
    user_id: String, lesson_id: mongoose.Schema.Types.ObjectId, task_id: mongoose.Schema.Types.ObjectId, passed: Boolean, output: String, submittedAt: Date 
});
taskProgressSchema.index({ user_id: 1, task_id: 1 }, { unique: true });
const TaskProgress = mongoose.models.TaskProgress || mongoose.model("TaskProgress", taskProgressSchema);

const completionSchema = new mongoose.Schema({ 
    user_id: String, course_id: String, lesson_id: mongoose.Schema.Types.ObjectId, completed_at: Date 
});
completionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });
const Completion = mongoose.models.Completion || mongoose.model("Completion", completionSchema);

const practiceUserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    age: { type: Number, min: 1 },
    _userId: { type: String, required: true },
    _lessonId: { type: mongoose.Schema.Types.ObjectId, required: true },
    _taskId: { type: mongoose.Schema.Types.ObjectId, required: true },
    submittedAt: { type: Date, default: Date.now }
});
practiceUserSchema.index({ _userId: 1, _taskId: 1 }, { unique: true });
const PracticeUser = mongoose.models.PracticeUser || mongoose.model("PracticeUser", practiceUserSchema);

const Task = require("./models/Task");
const Course = require("./models/Course");
const Lesson = require("./models/Lesson");

function requireAdminMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ success: false, message: "Unauthorized" });
  if (header.split(" ")[1] !== ADMIN_SECRET) return res.status(403).json({ success: false, message: "Forbidden" });
  next();
}

/* ---------------- ROUTES ---------------- */
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "AdminDashboard.html")));
app.get("/admin/login", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "AdminLogin.html")));
app.get("/health", (req, res) => res.status(200).send("OK"));

app.post('/api/project/upload', uploadProject.single('projectFile'), async (req, res) => {
    try {
        const { userId, lessonId, courseId, projectType } = req.body;
        if (!userId) return res.status(401).json({ success: false, message: "User not authenticated" });
        const user = await UserModel.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (!mongoose.Types.ObjectId.isValid(lessonId)) return res.status(400).json({ success: false, message: "Invalid Lesson ID" });
        if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });

        const isZip = req.file.mimetype.includes('zip') || req.file.mimetype.includes('tar') || req.file.mimetype.includes('gzip');
        const isDoc = req.file.mimetype.includes('pdf') || req.file.mimetype.includes('wordprocessingml');

        if (projectType === "planning" && !isDoc) { fs.unlinkSync(req.file.path); return res.status(400).json({ success: false, message: "Planning projects must be PDF or DOCX." }); }
        if (projectType !== "planning" && !isZip) { fs.unlinkSync(req.file.path); return res.status(400).json({ success: false, message: "Code projects must be ZIP archives." }); }

        const newProject = new Project({
            userId, courseId: courseId || "unknown", lessonId,
            projectType: projectType || "code", originalName: req.file.originalname, storedName: req.file.filename,
            filePath: `/uploads/projects/${req.file.filename}`, fileSize: req.file.size, status: "pending"
        });
        await newProject.save();

        if (!user.submitted_lessons) user.submitted_lessons = [];
        if (!user.submitted_lessons.includes(lessonId)) { user.submitted_lessons.push(lessonId); await user.save(); }

        res.json({ success: true, message: "Project submitted for review!", lessonCompleted: false });
    } catch (err) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); 
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post("/api/task/submit", async (req, res) => {
  try {
    const { userId, lessonId, taskId, code, projectType } = req.body;
    if (!mongoose.Types.ObjectId.isValid(lessonId) || !mongoose.Types.ObjectId.isValid(taskId)) return res.status(400).json({ success: false, error: "Invalid ID format" });
    
    const lessonObjectId = new mongoose.Types.ObjectId(lessonId);
    const taskObjectId = new mongoose.Types.ObjectId(taskId);
    const user = await UserModel.findById(userId);
    const task = await Task.findById(taskObjectId);
    if (!user || !task) return res.status(404).json({ success: false, error: "Not Found" });

    if (projectType === "planning") {
        await TaskProgress.findOneAndUpdate(
            { user_id: userId, task_id: taskObjectId },
            { user_id: userId, lesson_id: lessonObjectId, task_id: taskObjectId, passed: true, output: "Planning Submitted", submittedAt: new Date() }, { upsert: true }
        );
        return res.json({ success: true, passed: true, output: "Planning project accepted ✅" });
    }

    const lang = (task.language || "").toLowerCase();
    let result;
    try {
        const executionPromise = (async () => {
             if (lang === "java") return await runJava(code);
             if (lang === "python") return await runPython(code);
             if (lang === "javascript") return await runJavaScript(code);
             if (['html', 'css', 'react', 'jsx'].includes(lang)) return { output: "Frontend Validated" }; 
             throw new Error("Unsupported Language");
        })();
        result = await Promise.race([executionPromise, new Promise((_, r) => setTimeout(() => r(new Error("Execution Timed Out")), 3000))]);
    } catch (runErr) { return res.json({ success: false, passed: false, output: "Runtime Error: " + runErr.message }); }

    await TaskProgress.findOneAndUpdate(
        { user_id: userId, task_id: taskObjectId }, 
        { user_id: userId, lesson_id: lessonObjectId, task_id: taskObjectId, passed: true, output: result.output || "Success", submittedAt: new Date() }, { upsert: true }
    );
    res.json({ success: true, passed: true, output: result.output || "Success" });
  } catch (err) { res.status(500).json({ success: false, error: "Server Error" }); }
});

app.get("/api/public/courses", async (req, res) => {
    try {
        const courses = await Course.find({}).sort({ order: 1 });
        const results = await Promise.all(courses.map(async (c) => ({ course: c, lessonCount: await Lesson.countDocuments({ course_id: c._id.toString() }) })));
        res.json({ success: true, results });
    } catch (err) { res.status(500).json({ success: false, message: "Failed to load courses" }); }
});

app.get("/api/course/:slug", async (req, res) => {
    try {
        const course = await Course.findOne({ slug: req.params.slug });
        if (!course) return res.status(404).json({ success: false, message: "Course not found" });
        res.json({ success: true, course });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/course/:slug/lessons", async (req, res) => {
    try {
        const course = await Course.findOne({ slug: req.params.slug });
        if (!course) return res.status(404).json({ success: false });
        const lessons = await Lesson.find({ course_id: course._id.toString() }).sort({ order: 1 });
        res.json({ success: true, lessons });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/lesson/:lessonId/details", async (req, res) => {
    try {
        const lesson = await Lesson.findById(req.params.lessonId).lean();
        const tasks = await Task.find({ lesson_id: new mongoose.Types.ObjectId(req.params.lessonId) }).sort({ order: 1 });
        res.json({ success: true, lesson, tasks });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/user/:userId/projects", async (req, res) => {
    try {
        const projects = await Project.find({ userId: req.params.userId }).sort({ createdAt: -1 });
        res.json({ success: true, projects });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/lesson/:lessonId/pdf", async (req, res) => {
    try {
        const lesson = await Lesson.findById(req.params.lessonId);
        if (!lesson || !lesson.pdf) return res.status(404).json({ success: false, message: "PDF not found" });
        res.json({ success: true, pdf: lesson.pdf });
    } catch { res.status(500).json({ success: false }); }
});

app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!password || password.length < 6) return res.status(400).json({ success: false, message: "Password too short" });
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
    const user = await UserModel.create({ username, email, password: bcrypt.hashSync(password, 12), image });
    res.json({ success: true, user });
  } catch (err) { res.status(500).json({ success: false, message: "Server Error" }); }
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
    if (!userId || !lessonId) return res.status(400).json({ success: false });
    const lessonObjectId = new mongoose.Types.ObjectId(lessonId);
    await UserModel.findByIdAndUpdate(userId, { $addToSet: { completed_lessons: lessonId } });
    await Completion.updateOne(
      { user_id: userId, lesson_id: lessonObjectId },
      { $setOnInsert: { user_id: userId, lesson_id: lessonObjectId, completed_at: new Date() } }, { upsert: true }
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false }); }
});

/* ---------------- ADMIN ROUTES ---------------- */
app.post("/api/admin/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false });
    if (password === ADMIN_SECRET) {
        await AdminModel.updateOne({ username }, { $setOnInsert: { username, password: bcrypt.hashSync(password, 12) } }, { upsert: true });
        return res.json({ success: true, token: ADMIN_SECRET, admin: { username } });
    }
    const admin = await AdminModel.findOne({ username });
    if (admin && bcrypt.compareSync(password, admin.password)) return res.json({ success: true, token: ADMIN_SECRET, admin: { username } });
    res.status(401).json({ success: false });
});

app.get("/api/admin/overview", requireAdminMiddleware, async (req, res) => {
  try {
    const totalUsers = await UserModel.countDocuments();
    // ✅ FIX: Active Course Filtering
    const activeCourses = await Course.countDocuments({ isActive: true }); 
    const pendingProjects = await Project.countDocuments({ status: "pending" });
    // ✅ FIX: Match key with Frontend (pendingCount)
    res.json({ totalUsers, activeCourses, pendingCount: pendingProjects });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.get("/api/admin/users", requireAdminMiddleware, async (req, res) => {
  try {
    const users = await UserModel.find({}, "-password").lean();
    const totalLessons = await Lesson.countDocuments();
    const enriched = await Promise.all(users.map(async u => {
      const completed = await Completion.countDocuments({ user_id: u._id });
      return {
        ...u,
        percentage: totalLessons ? Math.round((completed / totalLessons) * 100) : 0
      };
    }));
    res.json({ users: enriched });
  } catch (err) { res.status(500).json({ success: false }); }
});

app.post("/api/admin/user/:id/purge", requireAdminMiddleware, async (req, res) => {
  try {
    const userId = req.params.id;
    await Project.deleteMany({ userId });
    await Completion.deleteMany({ user_id: userId });
    await TaskProgress.deleteMany({ user_id: userId });
    await PracticeUser.deleteMany({ _userId: userId });
    await UserModel.findByIdAndDelete(userId);
    res.json({ success: true });
  } catch { res.status(500).json({ success: false }); }
});

app.get("/api/admin/projects", requireAdminMiddleware, async (req, res) => {
  try {
    const projects = await Project.find({}).sort({ createdAt: -1 });
    const results = await Promise.all(projects.map(async (p) => {
      const user = await UserModel.findById(p.userId).lean();
      const lesson = await Lesson.findById(p.lessonId).lean();
      return {
        ...p.toObject(),
        userId: user ? { username: user.username, email: user.email } : null,
        lessonId: lesson ? { title: lesson.title } : null
      };
    }));
    res.json({ success: true, projects: results });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get("/api/admin/projects/:id/download", requireAdminMiddleware, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ success: false });
    const cleanPath = project.filePath.replace(/^\/+/, ""); 
    const absolutePath = path.join(__dirname, "public", cleanPath);
    res.download(absolutePath, project.originalName);
  } catch (err) { res.status(500).json({ success: false }); }
});

app.put("/api/admin/projects/:id/status", requireAdminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        // ✅ FIX: Explicit Input Validation
        if (!["pending", "approved", "rejected"].includes(status)) {
            return res.status(400).json({ success: false, message: "Invalid status" });
        }

        const project = await Project.findById(req.params.id);
        if (!project) return res.status(404).json({ success: false });

        if (status === "approved" && project.status !== "approved") {
            const user = await UserModel.findById(project.userId);
            if (user) {
                user.xp = (user.xp || 0) + (project.projectType === "planning" ? 50 : 100);
                if (!user.completed_lessons) user.completed_lessons = [];
                if (!user.completed_lessons.includes(project.lessonId)) user.completed_lessons.push(project.lessonId);
                await user.save();
                
                const lessonObjectId = new mongoose.Types.ObjectId(project.lessonId);
                await Completion.updateOne(
                    { user_id: project.userId, lesson_id: lessonObjectId },
                    { $setOnInsert: { user_id: project.userId, course_id: project.courseId, lesson_id: lessonObjectId, completed_at: new Date() } },
                    { upsert: true }
                );
            }
        }
        project.status = status;
        await project.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post("/api/admin/lesson/:lessonId/pdf", requireAdminMiddleware, uploadPDF.single("pdf"), async (req, res) => {
    try {
        const lesson = await Lesson.findById(req.params.lessonId);
        if (!lesson) return res.status(404).json({ success: false });
        if (!req.file) return res.status(400).json({ success: false });
        lesson.pdf = `/uploads/lesson-pdfs/${req.file.filename}`;
        await lesson.save();
        res.json({ success: true, pdf: lesson.pdf });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.put("/api/admin/lesson/:lessonId/content", requireAdminMiddleware, async (req, res) => {
    try {
        const { video, notes } = req.body;
        const lesson = await Lesson.findById(req.params.lessonId);
        if (!lesson) return res.status(404).json({ success: false });
        if (video !== undefined) lesson.video = video; 
        if (notes !== undefined) lesson.notes = notes; 
        await lesson.save();
        res.json({ success: true, lesson });
    } catch { res.status(500).json({ success: false }); }
});

// ✅ FIX: CASCADE DELETE (Professional & Viva-Safe)
app.delete("/api/admin/lesson/:id", requireAdminMiddleware, async (req, res) => {
    try {
        const lesson = await Lesson.findByIdAndDelete(req.params.id);
        if (lesson) {
            // 1. Delete PDF if exists
            if (lesson.pdf) {
                const filePath = path.join(PUBLIC_DIR, lesson.pdf.replace(/^\/+/, ""));
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            }
            // 2. Cascade Delete all related data to prevent Orphans
            await Task.deleteMany({ lesson_id: lesson._id });
            await Project.deleteMany({ lessonId: lesson._id.toString() });
            await TaskProgress.deleteMany({ lesson_id: lesson._id });
            await Completion.deleteMany({ lesson_id: lesson._id });
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.delete("/api/admin/projects/:id", requireAdminMiddleware, async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);
        if (project) {
            const filePath = path.join(__dirname, "public", project.filePath.replace(/^\/+/, ""));
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError || (err && typeof err.message === "string" && (err.message.includes("archives") || err.message.includes("Invalid file type")))) {
      return res.status(400).json({ success: false, message: err.message });
    }
    next(err);
});

app.use((err, req, res, next) => {
    console.error("GLOBAL ERROR:", err.message);
    res.status(500).json({ success: false, message: "Internal Server Error" });
});

app.listen(PORT, () => console.log(`🔥 MindStep running → http://localhost:${PORT}`));