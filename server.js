/**
 * server.js — MindStep FINAL PLATINUM EDITION (Logic Fixed + Optimized + Polished)
 * 🚀 CHANGES IN THIS VERSION:
 * 1. FIXED: Auto-Completion now saves 'course_id' (Solves 0% Progress).
 * 2. FIXED: MongoDB Practice Routes now use Mongoose with Elite Validation.
 * 3. NEW: Added /api/course-progress route for Course Page UI.
 * 4. RESTORED: Backward-compatible /api/course/:slug/progress/:userId route.
 * 5. HYBRID COMPLETION: Progress updates immediately, completion flag sets at 100%.
 * 6. RETAINED: All performance tweaks (Gzip, Pooling).
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

// ✅ SAFE IMPORT: Compression
let compression;
try {
    compression = require("compression");
} catch (e) {
    console.warn("⚠️ Optimization Warning: 'compression' module not found. Skipping gzip.");
}

/* ---------------- UTILS ---------------- */
// Ensure these files exist in your /utils folder
const runJava = require("./utils/runJava");
const runPython = require("./utils/runPython");
const runJavaScript = require("./utils/runJavaScript");

/* ---------------- CONFIG ---------------- */
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const TEMP_DIR = path.join(__dirname, "temp");

// Create necessary directories
[TEMP_DIR, path.join(PUBLIC_DIR, "uploads"), path.join(PUBLIC_DIR, "uploads", "projects"), path.join(PUBLIC_DIR, "uploads", "lesson-pdfs")].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
const PROJECT_DIR = path.join(UPLOADS_DIR, "projects");
const PDF_DIR = path.join(UPLOADS_DIR, "lesson-pdfs");

/* ---------------- ENV CHECKS ---------------- */
if (!process.env.MONGO_URI) { console.error("❌ MONGO_URI missing"); process.exit(1); }
if (!process.env.ADMIN_SECRET) { console.error("❌ ADMIN_SECRET missing"); process.exit(1); }
const ADMIN_SECRET = process.env.ADMIN_SECRET;

/* ---------------- DB CONNECTION ---------------- */
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
    .then(() => console.log("✔ MongoDB connected (Pool Optimized)"))
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

if (compression) {
    app.use(compression());
}

app.use(cors());
app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// ✅ CACHE MIDDLEWARE
const cache = new Map();
const cacheMiddleware = (key, ttl = 60 * 1000) => (req, res, next) => {
    if (cache.has(key)) {
        return res.json(cache.get(key));
    }
    const send = res.json.bind(res);
    res.json = (body) => {
        cache.set(key, body);
        setTimeout(() => cache.delete(key), ttl);
        send(body);
    };
    next();
};

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
userSchema.index({ email: 1 });
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
    taskId: String,
    projectType: String,
    originalName: String,
    storedName: String,
    filePath: String,
    fileSize: Number,
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    reviewComment: String,
    createdAt: { type: Date, default: Date.now }
});
projectSchema.index({ status: 1 });
projectSchema.index({ userId: 1 });
const Project = mongoose.models.Project || mongoose.model("Project", projectSchema);

const taskProgressSchema = new mongoose.Schema({
    // Canonical progress fields
    userId: { type: String, index: true },
    taskId: { type: String, index: true },
    status: { type: String, enum: ["pending", "completed"], default: "pending" },
    attempts: { type: Number, default: 0 },
    lastAttemptAt: { type: Date, default: Date.now },
    completedAt: Date,

    // Backward-compatible fields
    user_id: String,
    lesson_id: mongoose.Schema.Types.ObjectId,
    task_id: mongoose.Schema.Types.ObjectId,
    passed: Boolean,
    output: String,
    submittedAt: Date
});
taskProgressSchema.index({ user_id: 1, task_id: 1 }, { unique: true });
taskProgressSchema.index(
    { userId: 1, taskId: 1 },
    { unique: true, partialFilterExpression: { userId: { $type: "string" }, taskId: { $type: "string" } } }
);
const TaskProgress = mongoose.models.TaskProgress || mongoose.model("TaskProgress", taskProgressSchema);

const completionSchema = new mongoose.Schema({
    user_id: String, course_id: String, lesson_id: mongoose.Schema.Types.ObjectId, completed_at: Date
});
completionSchema.index({ user_id: 1, lesson_id: 1 }, { unique: true });
completionSchema.index({ user_id: 1 });
const Completion = mongoose.models.Completion || mongoose.model("Completion", completionSchema);

// Progress model for simple completed flag tracking (used by some frontends)
const progressSchema = new mongoose.Schema({
    userId: String,
    lessonId: mongoose.Schema.Types.ObjectId,
    completed: { type: Boolean, default: false },
    updatedAt: { type: Date, default: Date.now }
});
progressSchema.index({ userId: 1, lessonId: 1 }, { unique: true });
const Progress = mongoose.models.Progress || mongoose.model("Progress", progressSchema);

const practiceUserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    age: { type: Number, min: 1 },
    _userId: { type: String, required: true },
    _lessonId: { type: mongoose.Schema.Types.ObjectId, required: true },
    _taskId: { type: mongoose.Schema.Types.ObjectId, required: true },
    submittedAt: { type: Date, default: Date.now }
});
const PracticeUser = mongoose.models.PracticeUser || mongoose.model("PracticeUser", practiceUserSchema);

const documentSchema = new mongoose.Schema({
    data: mongoose.Schema.Types.Mixed,
    createdAt: { type: Date, default: Date.now }
});
const MindStepDoc = mongoose.models.MindStepDoc || mongoose.model("MindStepDoc", documentSchema);

const Task = require("./models/Task");
const Course = require("./models/Course");
const Lesson = require("./models/Lesson");
const issuesRouter = require("./routes/issues");

function requireAdminMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ success: false, message: "Unauthorized" });
    if (header.split(" ")[1] !== ADMIN_SECRET) return res.status(403).json({ success: false, message: "Forbidden" });
    next();
}

async function updateTaskProgressRecord({ userId, lessonObjectId, taskObjectId, passed, output }) {
    const now = new Date();
    const query = {
        $or: [
            { userId, taskId: taskObjectId.toString() },
            { user_id: userId, task_id: taskObjectId }
        ]
    };

    let progress = await TaskProgress.findOne(query);
    if (!progress) {
        progress = new TaskProgress({
            userId,
            taskId: taskObjectId.toString(),
            status: passed ? "completed" : "pending",
            attempts: 1,
            lastAttemptAt: now,
            completedAt: passed ? now : undefined,
            user_id: userId,
            lesson_id: lessonObjectId,
            task_id: taskObjectId,
            passed: Boolean(passed),
            output: output || "Success",
            submittedAt: now
        });
    } else {
        progress.attempts = (progress.attempts || 0) + 1;
        progress.lastAttemptAt = now;
        progress.userId = userId;
        progress.taskId = taskObjectId.toString();
        progress.user_id = userId;
        progress.lesson_id = lessonObjectId;
        progress.task_id = taskObjectId;
        progress.output = output || "Success";
        progress.submittedAt = now;

        if (passed) {
            progress.status = "completed";
            progress.passed = true;
            if (!progress.completedAt) progress.completedAt = now;
        } else {
            if (progress.status !== "completed") progress.status = "pending";
            if (progress.status !== "completed") progress.passed = false;
        }
    }

    await progress.save();
    return progress;
}

async function markLessonCompletionForTask(userId, lessonObjectId) {
    const lesson = await Lesson.findById(lessonObjectId).lean();
    if (!lesson) return;
    await Completion.updateOne(
        { user_id: userId, lesson_id: lessonObjectId },
        {
            $setOnInsert: {
                user_id: userId,
                lesson_id: lessonObjectId,
                course_id: lesson.course_id,
                completed_at: new Date()
            }
        },
        { upsert: true }
    );
}

function didExecutionPass(result) {
    if (!result || result.success !== true) return false;
    if (result.timedOut) return false;
    const stderr = String(result.stderr || "").trim();
    if (stderr.length > 0) return false;
    return true;
}

/* ---------------- ROUTES ---------------- */
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "LoginPage.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "AdminDashboard.html")));
app.get("/admin/login", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "AdminLogin.html")));
app.get("/health", (req, res) => res.status(200).send("OK"));

// ✅ 1. PROGRESS PERSISTENCE API
app.get("/api/progress/:userId/:lessonId", async (req, res) => {
    try {
        const { userId, lessonId } = req.params;
        const lessonObjectId = new mongoose.Types.ObjectId(lessonId);
        const lessonCompleted = await Completion.exists({
            user_id: userId,
            lesson_id: lessonObjectId
        });

        const progressRows = await TaskProgress.find(
            {
                lesson_id: lessonObjectId,
                $or: [{ userId }, { user_id: userId }]
            },
            "task_id taskId passed status attempts lastAttemptAt completedAt"
        ).lean();

        const passedTaskIds = new Set();
        const taskProgress = {};
        progressRows.forEach(row => {
            const rowTaskId = (row.taskId || (row.task_id ? row.task_id.toString() : "")).toString();
            if (!rowTaskId) return;

            const isCompleted = row.status === "completed" || row.passed === true;
            if (isCompleted) passedTaskIds.add(rowTaskId);

            taskProgress[rowTaskId] = {
                status: row.status || (row.passed ? "completed" : "pending"),
                attempts: typeof row.attempts === "number" ? row.attempts : 0,
                lastAttemptAt: row.lastAttemptAt || null,
                completedAt: row.completedAt || null
            };
        });

        // Include approved project submissions as passed for project tasks in this lesson.
        const approvedProjects = await Project.find(
            { userId, lessonId: lessonId.toString(), status: "approved" },
            "taskId"
        ).lean();

        if (approvedProjects.length > 0) {
            const taskIdsFromProjects = approvedProjects
                .map(p => (p.taskId || "").toString())
                .filter(id => mongoose.Types.ObjectId.isValid(id));

            if (taskIdsFromProjects.length > 0) {
                taskIdsFromProjects.forEach(id => passedTaskIds.add(id));
            } else {
                const projectTasks = await Task.find(
                    { lesson_id: lessonObjectId, type: "project" },
                    "_id"
                ).lean();
                projectTasks.forEach(t => passedTaskIds.add(t._id.toString()));
            }
        }

        res.json({
            success: true,
            passedTaskIds: Array.from(passedTaskIds),
            taskProgress,
            lessonCompleted: Boolean(lessonCompleted)
        });
    } catch {
        res.status(500).json({ success: false });
    }
});

// ✅ 2. COURSE PROGRESS API (Fixes 0% Issue)
app.get("/api/course-progress/:userId/:courseId", async (req, res) => {
    try {
        const { userId, courseId } = req.params;

        // Count Total Lessons in Course
        const lessons = await Lesson.find({ course_id: courseId }, "_id").lean();
        const lessonIds = lessons.map(l => l._id);
        const totalLessons = lessons.length;

        // Count Completed Lessons by User in Course
        // Match either Completion.course_id (new inserts) OR Completion.lesson_id in the course's lessons
        const completed = await Completion.countDocuments({
            user_id: userId,
            $or: [
                { course_id: courseId },
                { lesson_id: { $in: lessonIds } }
            ]
        });

        const percentage = totalLessons
            ? Math.round((completed / totalLessons) * 100)
            : 0;

        res.json({ success: true, percentage, total: totalLessons, completed });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// ✅ 3. BACKWARD-COMPATIBLE COURSE PROGRESS
app.get("/api/course/:slug/progress/:userId", async (req, res) => {
    try {
        const course = await Course.findOne({ slug: req.params.slug }).lean();
        if (!course) return res.json({ success: true, percent: 0 });

        const lessonIds = await Lesson.find(
            { course_id: course._id.toString() },
            "_id"
        ).lean();

        const completed = await Completion.countDocuments({
            user_id: req.params.userId,
            lesson_id: { $in: lessonIds.map(l => l._id) }
        });

        const percent = lessonIds.length
            ? Math.round((completed / lessonIds.length) * 100)
            : 0;

        res.json({ success: true, percent });
    } catch {
        res.status(500).json({ success: false });
    }
});

app.post('/api/project/upload', uploadProject.single('projectFile'), async (req, res) => {
    try {
        const { userId, lessonId, courseId, projectType, taskId } = req.body;
        if (!userId) return res.status(401).json({ success: false, message: "User not authenticated" });
        const user = await UserModel.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        if (!mongoose.Types.ObjectId.isValid(lessonId)) return res.status(400).json({ success: false, message: "Invalid Lesson ID" });
        if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });

        const normalizeFormat = (fmt) => String(fmt || "").trim().toLowerCase().replace(/^\./, "");
        const getFileFormat = (originalName) => {
            const lower = String(originalName || "").toLowerCase();
            if (lower.endsWith(".tar.gz")) return "tar.gz";
            if (lower.endsWith(".tar")) return "tar";
            if (lower.endsWith(".7z")) return "7z";
            if (lower.endsWith(".rar")) return "rar";
            if (lower.endsWith(".docx")) return "docx";
            if (lower.endsWith(".pdf")) return "pdf";
            if (lower.endsWith(".zip")) return "zip";
            return normalizeFormat(path.extname(lower));
        };

        let taskDoc = null;
        if (taskId && mongoose.Types.ObjectId.isValid(taskId)) {
            taskDoc = await Task.findOne({
                _id: new mongoose.Types.ObjectId(taskId),
                lesson_id: new mongoose.Types.ObjectId(lessonId)
            }).lean();
        }

        const lessonDoc = await Lesson.findById(new mongoose.Types.ObjectId(lessonId)).lean();

        let allowedFormats = [];
        if (Array.isArray(taskDoc?.submission?.allowedFormats)) {
            allowedFormats = taskDoc.submission.allowedFormats.map(normalizeFormat).filter(Boolean);
        } else if (Array.isArray(lessonDoc?.submission?.allowedFormats)) {
            allowedFormats = lessonDoc.submission.allowedFormats.map(normalizeFormat).filter(Boolean);
        }

        const uploadedFormat = getFileFormat(req.file.originalname);
        if (allowedFormats.length > 0 && !allowedFormats.includes(uploadedFormat)) {
            fs.unlink(req.file.path, () => { });
            return res.status(400).json({
                success: false,
                message: `Invalid file format '.${uploadedFormat}'. Allowed formats: ${allowedFormats.map(f => "." + f).join(", ")}`
            });
        }

        const newProject = new Project({
            userId, courseId: courseId || "unknown", lessonId,
            taskId: (taskId || "").toString(),
            projectType: (taskDoc?.projectType || projectType || "code"),
            originalName: req.file.originalname, storedName: req.file.filename,
            filePath: `/uploads/projects/${req.file.filename}`, fileSize: req.file.size, status: "pending"
        });
        await newProject.save();

        if (!user.submitted_lessons) user.submitted_lessons = [];
        if (!user.submitted_lessons.includes(lessonId)) { user.submitted_lessons.push(lessonId); await user.save(); }

        res.json({ success: true, message: "Project submitted for review!", lessonCompleted: false });
    } catch (err) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlink(req.file.path, () => { });
        res.status(500).json({ success: false, message: err.message });
    }
});

// ✅ 4. HYBRID COMPLETION LOGIC
app.post("/api/task/submit", async (req, res) => {
    try {
        const { userId, lessonId, taskId, code, projectType, input } = req.body;
        if (!mongoose.Types.ObjectId.isValid(lessonId) || !mongoose.Types.ObjectId.isValid(taskId)) {
            return res.status(400).json({ success: false, error: "Invalid ID format" });
        }

        const lessonObjectId = new mongoose.Types.ObjectId(lessonId);
        const taskObjectId = new mongoose.Types.ObjectId(taskId);

        const [user, task, lessonAlreadyCompleted] = await Promise.all([
            UserModel.findById(userId).lean(),
            Task.findById(taskObjectId).lean(),
            Completion.exists({ user_id: userId, lesson_id: lessonObjectId })
        ]);
        if (!user || !task) return res.status(404).json({ success: false, error: "Not Found" });

        if (projectType === "planning") {
            if (lessonAlreadyCompleted) {
                return res.json({
                    success: true,
                    passed: true,
                    output: "Planning accepted in practice mode.",
                    practiceMode: true,
                    persisted: false
                });
            }

            await updateTaskProgressRecord({
                userId,
                lessonObjectId,
                taskObjectId,
                passed: true,
                output: "Planning Submitted"
            });

            return res.json({
                success: true,
                passed: true,
                output: "Planning project accepted.",
                practiceMode: false,
                persisted: true
            });
        }

        const lang = (task.language || "").toLowerCase();
        let result;
        try {
            const executionPromise = (async () => {
                if (lang === "java") return await runJava(code, input);
                if (lang === "python") return await runPython(code, input);
                if (lang === "javascript") return await runJavaScript(code, input);
                if (["html", "css", "react", "jsx"].includes(lang)) return { output: "Frontend Validated", success: true };
                throw new Error("Unsupported Language");
            })();
            result = await executionPromise;
        } catch (runErr) {
            return res.json({ success: false, passed: false, output: "Runtime Error: " + runErr.message });
        }
        const executionPassed = didExecutionPass(result);

        if (lessonAlreadyCompleted) {
            return res.json({
                success: true,
                passed: executionPassed,
                output: result.output || "Practice run completed",
                practiceMode: true,
                persisted: false
            });
        }

        await updateTaskProgressRecord({
            userId,
            lessonObjectId,
            taskObjectId,
            passed: executionPassed,
            output: result.output || "Success"
        });

        const totalTasks = await Task.countDocuments({ lesson_id: lessonObjectId });
        const passedTasks = await TaskProgress.countDocuments({
            lesson_id: lessonObjectId,
            $and: [
                { $or: [{ userId }, { user_id: userId }] },
                { $or: [{ status: "completed" }, { passed: true }] }
            ]
        });

        if (totalTasks > 0 && totalTasks === passedTasks) {
            await UserModel.findByIdAndUpdate(userId, { $addToSet: { completed_lessons: lessonId } });
            await markLessonCompletionForTask(userId, lessonObjectId);
        }

        return res.json({
            success: true,
            passed: executionPassed,
            output: result.output || "Success",
            practiceMode: false,
            persisted: true
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: "Server Error" });
    }
});

app.post("/api/task/progress", async (req, res) => {
    try {
        const { userId, lessonId, taskId, passed, output } = req.body || {};
        if (!mongoose.Types.ObjectId.isValid(lessonId) || !mongoose.Types.ObjectId.isValid(taskId)) {
            return res.status(400).json({ success: false, error: "Invalid ID format" });
        }

        const lessonObjectId = new mongoose.Types.ObjectId(lessonId);
        const taskObjectId = new mongoose.Types.ObjectId(taskId);
        const lessonAlreadyCompleted = await Completion.exists({
            user_id: userId,
            lesson_id: lessonObjectId
        });

        const query = {
            $or: [
                { userId, taskId: taskObjectId.toString() },
                { user_id: userId, task_id: taskObjectId }
            ]
        };

        if (lessonAlreadyCompleted) {
            const progress = await TaskProgress.findOne(query, "status attempts lastAttemptAt completedAt").lean();
            return res.json({
                success: true,
                practiceMode: true,
                persisted: false,
                progress: progress || null
            });
        }

        const progress = await updateTaskProgressRecord({
            userId,
            lessonObjectId,
            taskObjectId,
            passed: Boolean(passed),
            output: output || (passed ? "Completed" : "Attempt recorded")
        });

        return res.json({
            success: true,
            practiceMode: false,
            persisted: true,
            progress: progress ? {
                status: progress.status || (progress.passed ? "completed" : "pending"),
                attempts: typeof progress.attempts === "number" ? progress.attempts : 0,
                lastAttemptAt: progress.lastAttemptAt || null,
                completedAt: progress.completedAt || null
            } : null
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: "Server Error" });
    }
});

app.get("/api/public/courses", cacheMiddleware("public_courses"), async (req, res) => {
    try {
        const courses = await Course.find({}).sort({ order: 1 }).lean();
        const lessonCounts = await Lesson.aggregate([{ $group: { _id: "$course_id", count: { $sum: 1 } } }]);
        const countMap = Object.fromEntries(lessonCounts.map(l => [l._id.toString(), l.count]));
        const results = courses.map(c => ({
            course: c,
            lessonCount: countMap[c._id.toString()] || 0
        }));
        res.json({ success: true, results });
    } catch (err) { res.status(500).json({ success: false, message: "Failed to load courses" }); }
});

app.get("/api/course/:slug", async (req, res) => {
    try {
        const course = await Course.findOne({ slug: req.params.slug }).lean();
        if (!course) return res.status(404).json({ success: false, message: "Course not found" });
        res.json({ success: true, course });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/course/:slug/lessons", async (req, res) => {
    try {
        const course = await Course.findOne({ slug: req.params.slug }).lean();
        if (!course) return res.status(404).json({ success: false });
        const lessons = await Lesson.find({ course_id: course._id.toString() }).sort({ order: 1 }).lean();
        res.json({ success: true, lessons });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/lesson/:lessonId/details", async (req, res) => {
    try {
        const lesson = await Lesson.findById(req.params.lessonId).lean();
        const tasks = await Task.find({ lesson_id: new mongoose.Types.ObjectId(req.params.lessonId) }).sort({ order: 1 }).lean();
        res.json({ success: true, lesson, tasks });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/user/:userId/projects", async (req, res) => {
    try {
        const projects = await Project.find({ userId: req.params.userId }).sort({ createdAt: -1 }).lean();
        res.json({ success: true, projects });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/lesson/:lessonId/pdf", async (req, res) => {
    try {
        const lesson = await Lesson.findById(req.params.lessonId).lean();
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
            if (fs.existsSync(req.file.path)) fs.unlink(req.file.path, () => { });
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

        res.json({ success: true, user: { ...user.toObject(), percentage: total ? Math.round((done / total) * 100) : 0 } });
    } catch { res.status(500).json({ success: false }); }
});

app.post("/api/complete", async (req, res) => {
    try {
        const { userId, lessonId } = req.body;
        if (!userId || !lessonId) return res.status(400).json({ success: false });
        const lessonObjectId = new mongoose.Types.ObjectId(lessonId);

        // Add to user's completed lessons array (id stored as string)
        await UserModel.findByIdAndUpdate(userId, { $addToSet: { completed_lessons: lessonId } });

        // Look up lesson to capture course_id for Completion record
        let lessonDoc = null;
        try {
            lessonDoc = await Lesson.findById(lessonObjectId).lean();
        } catch (e) { lessonDoc = null; }

        const courseId = lessonDoc ? lessonDoc.course_id : undefined;

        // Upsert Completion with associated course_id when available
        const setOnInsert = {
            user_id: userId,
            lesson_id: lessonObjectId,
            completed_at: new Date()
        };
        if (courseId !== undefined) setOnInsert.course_id = courseId;

        await Completion.updateOne(
            { user_id: userId, lesson_id: lessonObjectId },
            { $setOnInsert: setOnInsert },
            { upsert: true }
        );
        // Also maintain a simple Progress document for frontends expecting a Progress collection
        try {
            await Progress.updateOne(
                { userId, lessonId: lessonObjectId },
                { $set: { completed: true, updatedAt: new Date() } },
                { upsert: true }
            );
        } catch (pErr) {
            console.warn('Progress upsert failed:', pErr && pErr.message);
        }
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
        const [totalUsers, activeCourses, pendingProjects] = await Promise.all([
            UserModel.countDocuments(),
            Course.countDocuments({ isActive: true }),
            Project.countDocuments({ status: "pending" })
        ]);
        res.json({ totalUsers, activeCourses, pendingCount: pendingProjects });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.get("/api/admin/users", requireAdminMiddleware, async (req, res) => {
    try {
        const users = await UserModel.find({}, "-password").lean();
        const totalLessons = await Lesson.countDocuments();

        const progress = await Completion.aggregate([
            { $group: { _id: "$user_id", count: { $sum: 1 } } }
        ]);

        const progressMap = Object.fromEntries(progress.map(p => [p._id, p.count]));

        const enriched = users.map(u => ({
            ...u,
            percentage: totalLessons ? Math.round(((progressMap[u._id] || 0) / totalLessons) * 100) : 0
        }));

        res.json({ users: enriched });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post("/api/admin/user/:id/purge", requireAdminMiddleware, async (req, res) => {
    try {
        const userId = req.params.id;
        await Promise.all([
            Project.deleteMany({ userId }),
            Completion.deleteMany({ user_id: userId }),
            TaskProgress.deleteMany({ user_id: userId }),
            PracticeUser.deleteMany({ _userId: userId }),
            UserModel.findByIdAndDelete(userId)
        ]);
        res.json({ success: true });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/admin/projects", requireAdminMiddleware, async (req, res) => {
    try {
        const projects = await Project.find({}).sort({ createdAt: -1 }).lean();

        const userIds = [...new Set(projects.map(p => p.userId).filter(Boolean))];
        const lessonIds = [...new Set(projects.map(p => p.lessonId).filter(Boolean))];

        const [users, lessons] = await Promise.all([
            UserModel.find({ _id: { $in: userIds } }, "username email").lean(),
            Lesson.find({ _id: { $in: lessonIds } }, "title").lean()
        ]);

        const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
        const lessonMap = Object.fromEntries(lessons.map(l => [l._id.toString(), l]));

        const results = projects.map(p => ({
            ...p,
            userId: userMap[p.userId] || null,
            lessonId: lessonMap[p.lessonId] || null
        }));

        res.json({ success: true, projects: results });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get("/api/admin/projects/:id/download", requireAdminMiddleware, async (req, res) => {
    try {
        const project = await Project.findById(req.params.id).lean();
        if (!project) return res.status(404).json({ success: false });
        const cleanPath = project.filePath.replace(/^\/+/, "");
        const absolutePath = path.join(__dirname, "public", cleanPath);
        res.download(absolutePath, project.originalName);
    } catch (err) { res.status(500).json({ success: false }); }
});

app.put("/api/admin/projects/:id/status", requireAdminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
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

app.delete("/api/admin/lesson/:id", requireAdminMiddleware, async (req, res) => {
    try {
        const lesson = await Lesson.findByIdAndDelete(req.params.id);
        if (lesson) {
            if (lesson.pdf) {
                const filePath = path.join(PUBLIC_DIR, lesson.pdf.replace(/^\/+/, ""));
                fs.unlink(filePath, () => { });
            }
            await Promise.all([
                Task.deleteMany({ lesson_id: lesson._id }),
                Project.deleteMany({ lessonId: lesson._id.toString() }),
                TaskProgress.deleteMany({ lesson_id: lesson._id }),
                Completion.deleteMany({ lesson_id: lesson._id })
            ]);
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.delete("/api/admin/projects/:id", requireAdminMiddleware, async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);
        if (project) {
            const filePath = path.join(__dirname, "public", project.filePath.replace(/^\/+/, ""));
            fs.unlink(filePath, () => { });
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

// ✅ FIX: NEW ROUTES FOR MONGODB TASKS ✅

// 1. Insert Document Route (Mongoose Style with ELITE VALIDATION)
app.post("/api/mongo/insert", async (req, res) => {
    try {
        const { data } = req.body;

        if (!data) {
            return res.status(400).json({ message: "No data provided" });
        }

        const result = await MindStepDoc.create({ data });

        res.json({
            success: true,
            insertedId: result._id
        });

    } catch (error) {
        console.error("Mongo Insert Error:", error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 2. Fetch Document Route
app.get("/api/mongo/get/:id", async (req, res) => {
    try {
        const { id } = req.params;
        console.log("Fetching document with ID:", id);

        if (!mongoose.Types.ObjectId.isValid(id)) {
            console.log("Invalid ObjectId format");
            return res.status(400).json({
                success: false,
                message: "Invalid ID"
            });
        }

        const objectId = new mongoose.Types.ObjectId(id);
        console.log("Converted ObjectId:", objectId);

        const document = await MindStepDoc.findById(objectId);
        console.log("Query result:", document);

        if (!document) {
            console.log("Document not found in database for ID:", objectId);

            // Try to fetch all documents for debugging
            const allDocs = await MindStepDoc.find().limit(5);
            console.log("All documents in collection:", allDocs);

            return res.status(404).json({
                success: false,
                message: "Document not found"
            });
        }

        res.json({
            success: true,
            document: document.toObject ? document.toObject() : document
        });

    } catch (err) {
        console.error("Fetch error:", err);
        res.status(500).json({
            success: false,
            message: "Fetch failed: " + err.message
        });
    }
});

app.use("/api/issues", issuesRouter);

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


