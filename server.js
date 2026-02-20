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
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const PDFDocument = require("pdfkit");
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

// Always serve latest HTML (avoids stale UI cache during active development)
app.use((req, res, next) => {
    if (req.path && req.path.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
    }
    next();
});

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
            "application/zip",
            "application/x-zip-compressed",
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "text/plain"
        ];
        if (allowedMimes.includes(file.mimetype)) cb(null, true);
        else {
            const ext = path.extname(file.originalname).toLowerCase();
            if ([".zip", ".pdf", ".docx", ".txt"].includes(ext)) cb(null, true);
            else cb(new Error("Invalid file type. Allowed: .zip, .docx, .pdf, .txt"));
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
    adminFeedback: { type: String, default: "" },
    reviewComment: String,
    reviewedAt: Date,
    reviewedBy: String,
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

const certificateSchema = new mongoose.Schema({
    userId: { type: String, required: true, index: true },
    courseId: { type: String, required: true, index: true },
    certificateId: { type: String, required: true, unique: true, index: true },
    userName: { type: String, default: "" },
    courseName: { type: String, default: "" },
    completionDate: { type: Date, default: Date.now },
    qrVerificationLink: { type: String, default: "" },
    finalProjectId: { type: mongoose.Schema.Types.ObjectId, ref: "Project" },
    issuedAt: { type: Date, default: Date.now }
}, { timestamps: true });
certificateSchema.index({ userId: 1, courseId: 1 }, { unique: true });
const Certificate = mongoose.models.Certificate || mongoose.model("Certificate", certificateSchema);

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

function normalizeCourseId(courseId) {
    return String(courseId || "").trim();
}

function buildCourseCode(courseLike, fallbackCourseId) {
    const raw = String(
        courseLike?.slug ||
        courseLike?.title ||
        fallbackCourseId ||
        "course"
    ).trim().toUpperCase();
    const code = raw
        .replace(/[^A-Z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .split("-")
        .filter(Boolean)
        .slice(0, 2)
        .join("")
        .slice(0, 8);
    return code || "COURSE";
}

function createCertificateId({ courseCode }) {
    let random = "";
    while (random.length < 8) {
        random += crypto.randomBytes(6).toString("base64").replace(/[^A-Z0-9]/gi, "").toUpperCase();
    }
    random = random.slice(0, 8);
    return `MS-${String(courseCode || "COURSE").toUpperCase()}-${random}`;
}

function buildCertificateQrLink(req, certificateId) {
    return `${req.protocol}://${req.get("host")}/api/certificate-verify/${encodeURIComponent(certificateId)}`;
}

async function getCourseLessons(courseId) {
    return Lesson.find({ course_id: normalizeCourseId(courseId) }, "_id title order type").sort({ order: 1 }).lean();
}

async function evaluateCourseCertificateEligibility({ userId, courseId }) {
    const normalizedCourseId = normalizeCourseId(courseId);
    const lessons = await getCourseLessons(normalizedCourseId);
    const lessonIds = lessons.map(l => l._id);
    const lessonIdStrings = lessonIds.map(id => id.toString());

    if (lessonIds.length === 0) {
        return {
            eligible: false,
            allLessonsCompleted: false,
            finalProjectRequired: false,
            finalProjectStatus: "not_required",
            finalLessonId: null,
            finalProject: null,
            allProjectsApproved: false,
            projectApprovals: [],
            completedLessonIds: []
        };
    }

    const completionRows = await Completion.find(
        { user_id: userId, lesson_id: { $in: lessonIds } },
        "lesson_id"
    ).lean();
    const completedSet = new Set(completionRows.map(row => row.lesson_id && row.lesson_id.toString()).filter(Boolean));
    const allLessonsCompleted = lessonIdStrings.every(id => completedSet.has(id));

    const projectLessons = lessons.filter((row) => String(row?.type || "").toLowerCase() === "project");
    const finalLesson = lessons.reduce((acc, row) => {
        if (!acc) return row;
        const orderA = Number(acc.order) || 0;
        const orderB = Number(row.order) || 0;
        return orderB >= orderA ? row : acc;
    }, null);
    const finalProjectLesson = projectLessons.reduce((acc, row) => {
        if (!acc) return row;
        const orderA = Number(acc.order) || 0;
        const orderB = Number(row.order) || 0;
        return orderB >= orderA ? row : acc;
    }, null);

    const finalLessonId = finalLesson ? finalLesson._id.toString() : null;
    const finalProjectRequired = projectLessons.length > 0;

    const projectApprovals = await Promise.all(projectLessons.map(async (projectLesson) => {
        const lessonId = projectLesson._id.toString();
        const latestSubmission = await Project.findOne({
            userId,
            lessonId
        }).sort({ createdAt: -1, updatedAt: -1 }).lean();
        const status = latestSubmission
            ? String(latestSubmission.status || "not_submitted").toLowerCase()
            : "not_submitted";
        return {
            lessonId,
            lessonTitle: String(projectLesson.title || ""),
            status,
            submissionId: latestSubmission?._id ? latestSubmission._id.toString() : null,
            reviewedAt: latestSubmission?.reviewedAt || null,
            adminFeedback: latestSubmission?.adminFeedback || latestSubmission?.reviewComment || "",
            submission: latestSubmission || null
        };
    }));

    const allProjectsApproved = finalProjectRequired
        ? projectApprovals.every(item => item.status === "approved")
        : true;

    let finalProject = null;
    let finalProjectStatus = finalProjectRequired ? "not_submitted" : "not_required";
    if (finalProjectLesson) {
        const matched = projectApprovals.find(item => item.lessonId === finalProjectLesson._id.toString()) || null;
        finalProject = matched?.submission || null;
        finalProjectStatus = matched?.status || "not_submitted";
    }

    const eligible = Boolean(allLessonsCompleted && allProjectsApproved);

    return {
        eligible,
        allLessonsCompleted,
        finalProjectRequired,
        finalProjectStatus,
        finalLessonId,
        finalProject,
        allProjectsApproved,
        projectApprovals,
        completedLessonIds: Array.from(completedSet)
    };
}

async function ensureCertificateState({ req, userId, courseId, issueIfEligible = false }) {
    const normalizedCourseId = normalizeCourseId(courseId);
    const eligibility = await evaluateCourseCertificateEligibility({ userId, courseId: normalizedCourseId });
    const existing = await Certificate.findOne({ userId, courseId: normalizedCourseId }).lean();
    const claimable = Boolean(eligibility.eligible && !existing);

    if (!eligibility.eligible) {
        if (existing) {
            await Certificate.deleteOne({ _id: existing._id });
        }
        return {
            certificate: null,
            issued: false,
            revoked: Boolean(existing),
            claimable: false,
            ...eligibility
        };
    }

    if (existing) {
        return {
            certificate: existing,
            issued: false,
            revoked: false,
            claimable: false,
            ...eligibility
        };
    }

    if (!issueIfEligible) {
        return {
            certificate: null,
            issued: false,
            revoked: false,
            claimable,
            ...eligibility
        };
    }

    const [user, course] = await Promise.all([
        UserModel.findById(userId, "username").lean(),
        Course.findById(normalizedCourseId, "title slug").lean()
    ]);
    const issuedAt = new Date();
    const courseCode = buildCourseCode(course, normalizedCourseId);
    const certificateId = createCertificateId({ courseCode });
    const qrVerificationLink = buildCertificateQrLink(req, certificateId);

    const created = await Certificate.create({
        userId,
        courseId: normalizedCourseId,
        certificateId,
        userName: String(user?.username || ""),
        courseName: String(course?.title || ""),
        completionDate: issuedAt,
        qrVerificationLink,
        finalProjectId: eligibility.finalProject?._id || undefined,
        issuedAt
    });

    return {
        certificate: created.toObject(),
        issued: true,
        revoked: false,
        claimable: false,
        ...eligibility
    };
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
        const [lessonCompletedByCompletion, latestProjectSubmission] = await Promise.all([
            Completion.exists({
                user_id: userId,
                lesson_id: lessonObjectId
            }),
            Project.findOne({
                userId,
                lessonId: lessonId.toString()
            }).sort({ createdAt: -1, updatedAt: -1 }).lean()
        ]);
        const lessonApprovedByProject = Boolean(latestProjectSubmission && latestProjectSubmission.status === "approved");

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
        const submittedProjects = await Project.find(
            { userId, lessonId: lessonId.toString(), status: "approved" },
            "taskId"
        ).lean();

        if (submittedProjects.length > 0) {
            const taskIdsFromProjects = submittedProjects
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
            lessonCompleted: Boolean(lessonCompletedByCompletion || lessonApprovedByProject),
            projectSubmission: latestProjectSubmission
                ? {
                    status: String(latestProjectSubmission.status || "").toLowerCase(),
                    adminFeedback: latestProjectSubmission.adminFeedback || latestProjectSubmission.reviewComment || "",
                    reviewedAt: latestProjectSubmission.reviewedAt || null,
                    createdAt: latestProjectSubmission.createdAt || null,
                    originalName: latestProjectSubmission.originalName || ""
                }
                : null
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
        const lessonIdStrings = lessons.map(l => l._id.toString());
        const totalLessons = lessons.length;

        // Count completed lessons by user in course:
        // 1) Completion records
        // 2) Approved project lessons (fallback in case completion record is missing)
        const [completionRows, submittedProjectRows] = await Promise.all([
            Completion.find(
                {
                    user_id: userId,
                    $or: [
                        { course_id: courseId },
                        { lesson_id: { $in: lessonIds } }
                    ]
                },
                "lesson_id"
            ).lean(),
            Project.find(
                {
                    userId,
                    lessonId: { $in: lessonIdStrings },
                    status: "approved"
                },
                "lessonId"
            ).lean()
        ]);

        const completedLessonIds = new Set();
        completionRows.forEach(row => {
            if (row.lesson_id) completedLessonIds.add(row.lesson_id.toString());
        });
        submittedProjectRows.forEach(row => {
            if (row.lessonId) completedLessonIds.add(String(row.lessonId));
        });
        const completed = completedLessonIds.size;

        const percentage = totalLessons
            ? Math.round((completed / totalLessons) * 100)
            : 0;

        res.json({
            success: true,
            percentage,
            total: totalLessons,
            completed,
            completedLessonIds: Array.from(completedLessonIds)
        });
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

        const lessonObjectIds = lessonIds.map(l => l._id);
        const lessonIdStrings = lessonIds.map(l => l._id.toString());
        const [completionRows, submittedProjectRows] = await Promise.all([
            Completion.find(
                {
                    user_id: req.params.userId,
                    lesson_id: { $in: lessonObjectIds }
                },
                "lesson_id"
            ).lean(),
            Project.find(
                {
                    userId: req.params.userId,
                    lessonId: { $in: lessonIdStrings },
                    status: "approved"
                },
                "lessonId"
            ).lean()
        ]);

        const completedLessonIds = new Set();
        completionRows.forEach(row => {
            if (row.lesson_id) completedLessonIds.add(row.lesson_id.toString());
        });
        submittedProjectRows.forEach(row => {
            if (row.lessonId) completedLessonIds.add(String(row.lessonId));
        });

        const percent = lessonIds.length
            ? Math.round((completedLessonIds.size / lessonIds.length) * 100)
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
            if (lower.endsWith(".txt")) return "txt";
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

        const planningByTitle = /planning/i.test(String(taskDoc?.title || lessonDoc?.title || ""));
        const projectTypeCandidate = String(
            taskDoc?.projectType || projectType || (planningByTitle ? "planning" : "code")
        ).trim().toLowerCase();
        const resolvedProjectType = ["planning", "code"].includes(projectTypeCandidate)
            ? projectTypeCandidate
            : (planningByTitle ? "planning" : "code");

        if (resolvedProjectType === "planning") {
            // Planning submissions can be document-based or archived project proof.
            allowedFormats = ["zip", "docx", "pdf", "txt"];
        } else if (allowedFormats.length === 0) {
            // Deployment/code submissions default to ZIP only.
            allowedFormats = ["zip"];
        }

        const uploadedFormat = getFileFormat(req.file.originalname);
        if (allowedFormats.length > 0 && !allowedFormats.includes(uploadedFormat)) {
            fs.unlink(req.file.path, () => { });
            return res.status(400).json({
                success: false,
                message: `Invalid file format '.${uploadedFormat}'. Allowed formats: ${allowedFormats.map(f => "." + f).join(", ")}`
            });
        }

        const lessonCourseId = String(lessonDoc?.course_id || "").trim();
        let resolvedCourseId = lessonCourseId;
        if (!resolvedCourseId) {
            const requestedCourse = normalizeCourseId(courseId);
            if (requestedCourse) {
                if (mongoose.Types.ObjectId.isValid(requestedCourse)) {
                    resolvedCourseId = requestedCourse;
                } else {
                    const courseBySlug = await Course.findOne({ slug: requestedCourse }, "_id").lean();
                    if (courseBySlug?._id) {
                        resolvedCourseId = courseBySlug._id.toString();
                    }
                }
            }
        }
        if (!resolvedCourseId) resolvedCourseId = "unknown";
        const newProject = new Project({
            userId, courseId: resolvedCourseId, lessonId,
            taskId: (taskId || "").toString(),
            projectType: resolvedProjectType,
            originalName: req.file.originalname, storedName: req.file.filename,
            filePath: `/uploads/projects/${req.file.filename}`,
            fileSize: req.file.size,
            status: "pending",
            adminFeedback: "",
            reviewedAt: null
        });
        await newProject.save();

        if (!user.submitted_lessons) user.submitted_lessons = [];
        if (!user.submitted_lessons.includes(lessonId)) { user.submitted_lessons.push(lessonId); await user.save(); }

        res.json({
            success: true,
            message: "Project submitted for review!",
            lessonCompleted: false,
            project: {
                status: newProject.status,
                adminFeedback: "",
                reviewedAt: null,
                createdAt: newProject.createdAt,
                originalName: newProject.originalName
            }
        });
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

function lessonContentScore(lessonDoc) {
    if (!lessonDoc || typeof lessonDoc !== "object") return 0;
    const content = lessonDoc.lesson && typeof lessonDoc.lesson === "object" ? lessonDoc.lesson : {};
    const listSize = (value) => Array.isArray(value) ? value.filter(Boolean).length : 0;

    let score = 0;
    if (typeof content.intro === "string" && content.intro.trim()) score += 2;
    score += Math.min(5, listSize(content.learningOutcomes));
    score += Math.min(5, listSize(content.deepExplanation));
    score += Math.min(4, listSize(content.conceptBreakdown));
    score += Math.min(5, listSize(content.stepByStepImplementation || content.implementationSteps));
    if (content.requiredFolderStructure && (
        (Array.isArray(content.requiredFolderStructure.structure) && content.requiredFolderStructure.structure.length > 0) ||
        (typeof content.requiredFolderStructure === "string" && content.requiredFolderStructure.trim())
    )) {
        score += 5;
    }
    score += Math.min(5, listSize(content.adminEvaluationCriteria));
    score += Math.min(5, listSize(content.whyImportant));
    score += Math.min(5, listSize(content.commonMistakes));
    if (typeof content.summary === "string" && content.summary.trim()) score += 2;
    if (typeof lessonDoc.description === "string" && lessonDoc.description.trim()) score += 1;
    return score;
}

function normalizeObjectIdLike(value) {
    if (!value) return "";
    if (typeof value === "string") return value.trim();
    if (typeof value === "object") {
        if (typeof value.$oid === "string") return value.$oid.trim();
        if (typeof value.toString === "function") {
            const text = String(value.toString()).trim();
            if (text && text !== "[object Object]") return text;
        }
    }
    return "";
}

function normalizeDateLike(value) {
    if (!value) return 0;
    if (typeof value === "object" && value.$date) {
        const ts = new Date(value.$date).getTime();
        return Number.isFinite(ts) ? ts : 0;
    }
    const ts = new Date(value).getTime();
    return Number.isFinite(ts) ? ts : 0;
}

function lessonRecencyTs(lessonDoc) {
    const value = lessonDoc?.updatedAt || lessonDoc?.createdAt || lessonDoc?.created_at || 0;
    return normalizeDateLike(value);
}

function normalizeLessonTitle(value) {
    return String(value || "").trim().toLowerCase();
}

function chooseBetterLesson(first, second) {
    const firstScore = lessonContentScore(first);
    const secondScore = lessonContentScore(second);
    if (secondScore > firstScore) return second;
    if (secondScore < firstScore) return first;
    return lessonRecencyTs(second) > lessonRecencyTs(first) ? second : first;
}

function dedupeLessonsForCourse(lessons) {
    const byKey = new Map();
    for (const lesson of lessons || []) {
        const order = Number.isFinite(Number(lesson?.order)) ? Number(lesson.order) : -1;
        const title = String(lesson?.title || "").trim().toLowerCase();
        const key = `${order}::${title || String(lesson?._id || "")}`;
        const existing = byKey.get(key);
        byKey.set(key, existing ? chooseBetterLesson(existing, lesson) : lesson);
    }
    return [...byKey.values()].sort((a, b) => {
        const orderA = Number.isFinite(Number(a?.order)) ? Number(a.order) : 0;
        const orderB = Number.isFinite(Number(b?.order)) ? Number(b.order) : 0;
        if (orderA !== orderB) return orderA - orderB;
        return String(a?.title || "").localeCompare(String(b?.title || ""));
    });
}

const localLessonFileCache = {
    path: "",
    mtimeMs: 0,
    docs: []
};

function getLocalLessonSourceCandidates() {
    const envPath = String(process.env.LESSON_SOURCE_PATH || "").trim();
    const candidates = [];
    if (envPath) {
        candidates.push(path.resolve(envPath));
    }
    candidates.push(
        path.join(process.cwd(), "mindstep.lessons.json"),
        path.resolve(process.cwd(), "..", "mindstep.lessons.json")
    );

    const seen = new Set();
    const existing = [];
    for (const candidate of candidates) {
        const resolved = path.resolve(candidate);
        if (seen.has(resolved)) continue;
        seen.add(resolved);
        try {
            if (!fs.existsSync(resolved)) continue;
            const stat = fs.statSync(resolved);
            existing.push({ path: resolved, mtimeMs: stat.mtimeMs || 0 });
        } catch (_) { }
    }
    return existing.sort((a, b) => {
        if (b.mtimeMs !== a.mtimeMs) return b.mtimeMs - a.mtimeMs;
        return b.path.length - a.path.length;
    });
}

function normalizeParsedLessonDocs(parsed) {
    if (Array.isArray(parsed)) return parsed.filter(doc => doc && typeof doc === "object");
    if (!parsed || typeof parsed !== "object") return [];

    const nested = parsed.docs || parsed.lessons || parsed.documents || parsed.items || parsed.data;
    if (Array.isArray(nested)) return nested.filter(doc => doc && typeof doc === "object");

    if (parsed.lesson || parsed.title || parsed.course_id || parsed._id) {
        return [parsed];
    }
    return [];
}

function parseLessonDocs(rawText) {
    const raw = String(rawText || "").replace(/^\uFEFF/, "");
    const attempts = [raw];

    // Support files copied from MongoDB Compass that include block comments.
    const noBlockComments = raw.replace(/\/\*[\s\S]*?\*\//g, "").trim();
    if (noBlockComments && noBlockComments !== raw) attempts.push(noBlockComments);

    for (const candidate of attempts) {
        try {
            const parsed = JSON.parse(candidate);
            const docs = normalizeParsedLessonDocs(parsed);
            if (docs.length > 0) return docs;
        } catch (_) { }
    }
    return [];
}

function readLocalLessonDocs() {
    const sources = getLocalLessonSourceCandidates();
    if (sources.length === 0) return [];

    for (const source of sources) {
        try {
            if (
                localLessonFileCache.path === source.path &&
                localLessonFileCache.mtimeMs === source.mtimeMs &&
                Array.isArray(localLessonFileCache.docs)
            ) {
                return localLessonFileCache.docs;
            }

            const raw = fs.readFileSync(source.path, "utf8");
            const docs = parseLessonDocs(raw);
            if (docs.length > 0) {
                localLessonFileCache.path = source.path;
                localLessonFileCache.mtimeMs = source.mtimeMs;
                localLessonFileCache.docs = docs;
                return docs;
            }
        } catch (_) { }
    }

    return [];
}

function findLocalLessonCandidates(requestedLessonId, baseLesson) {
    const docs = readLocalLessonDocs();
    if (!Array.isArray(docs) || docs.length === 0) return [];

    const requestedId = normalizeObjectIdLike(requestedLessonId);
    const baseId = normalizeObjectIdLike(baseLesson?._id);
    const baseTitle = normalizeLessonTitle(baseLesson?.title);
    const baseCourseId = String(baseLesson?.course_id || "").trim();
    const baseOrder = Number(baseLesson?.order);

    return docs.filter((doc) => {
        const docId = normalizeObjectIdLike(doc?._id);
        if (requestedId && docId === requestedId) return true;
        if (baseId && docId === baseId) return true;

        const sameCourse = String(doc?.course_id || "").trim() === baseCourseId;
        const sameOrder = Number(doc?.order) === baseOrder;
        const sameTitle = normalizeLessonTitle(doc?.title) === baseTitle;
        return Boolean(sameCourse && sameOrder && sameTitle);
    });
}

function mergeLessonWithLocalSource(baseLesson, requestedLessonId) {
    if (!baseLesson || typeof baseLesson !== "object") return baseLesson;

    const localCandidates = findLocalLessonCandidates(requestedLessonId, baseLesson);
    if (!Array.isArray(localCandidates) || localCandidates.length === 0) return baseLesson;
    const requestedId = normalizeObjectIdLike(requestedLessonId);
    const exactMatch = localCandidates.find(candidate => {
        return requestedId && normalizeObjectIdLike(candidate?._id) === requestedId;
    }) || null;

    let bestLocal = exactMatch || localCandidates[0];
    for (const candidate of localCandidates) {
        if (candidate === bestLocal) continue;
        bestLocal = chooseBetterLesson(bestLocal, candidate);
    }

    if (!exactMatch && lessonContentScore(bestLocal) < lessonContentScore(baseLesson)) return baseLesson;

    const merged = { ...baseLesson, ...bestLocal };
    merged._id = baseLesson._id;
    merged.course_id = baseLesson.course_id;
    merged.order = baseLesson.order;
    if (baseLesson.lesson || bestLocal.lesson) {
        merged.lesson = {
            ...(baseLesson.lesson && typeof baseLesson.lesson === "object" ? baseLesson.lesson : {}),
            ...(bestLocal.lesson && typeof bestLocal.lesson === "object" ? bestLocal.lesson : {})
        };
    }
    return merged;
}

async function resolveBestLessonVariant(lessonDoc) {
    if (!lessonDoc || !lessonDoc.course_id) return lessonDoc;

    const sameOrderCandidates = await Lesson.find({
        course_id: lessonDoc.course_id,
        order: lessonDoc.order
    }).lean();
    if (!Array.isArray(sameOrderCandidates) || sameOrderCandidates.length === 0) return lessonDoc;

    const baseTitle = normalizeLessonTitle(lessonDoc.title);
    const candidates = sameOrderCandidates.filter(candidate => {
        // Never replace a lesson with a different title.
        return normalizeLessonTitle(candidate?.title) === baseTitle;
    });
    if (candidates.length === 0) return lessonDoc;

    let best = lessonDoc;
    for (const candidate of candidates) {
        best = chooseBetterLesson(best, candidate);
    }
    return best;
}

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
        const rawLessons = await Lesson.find({ course_id: course._id.toString() }).sort({ order: 1, updatedAt: -1, createdAt: -1 }).lean();
        const lessons = dedupeLessonsForCourse(rawLessons);
        res.json({ success: true, lessons });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/lesson/:lessonId/details", async (req, res) => {
    try {
        const requestedLesson = await Lesson.findById(req.params.lessonId).lean();
        if (!requestedLesson) return res.status(404).json({ success: false, message: "Lesson not found" });

        const resolvedLesson = await resolveBestLessonVariant(requestedLesson);
        const lesson = mergeLessonWithLocalSource(resolvedLesson, req.params.lessonId);
        const lessonTaskId = new mongoose.Types.ObjectId(String(lesson._id));
        const tasks = await Task.find({ lesson_id: lessonTaskId }).sort({ order: 1 }).lean();
        res.json({ success: true, lesson, tasks });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/user/:userId/projects", async (req, res) => {
    try {
        const projects = await Project.find({ userId: req.params.userId }).sort({ createdAt: -1 }).lean();
        res.json({ success: true, projects });
    } catch { res.status(500).json({ success: false }); }
});

app.get("/api/certificate/:userId/:courseId", async (req, res) => {
    try {
        const { userId, courseId } = req.params;
        const certResult = await ensureCertificateState({ req, userId, courseId, issueIfEligible: false });
        const latestProject = certResult.finalProject || null;

        return res.json({
            success: true,
            certificateAvailable: Boolean(certResult.certificate),
            certificate: certResult.certificate
                ? {
                    certificateId: certResult.certificate.certificateId,
                    userName: certResult.certificate.userName,
                    courseName: certResult.certificate.courseName,
                    completionDate: certResult.certificate.completionDate,
                    qrVerificationLink: certResult.certificate.qrVerificationLink
                }
                : null,
            claimable: Boolean(certResult.claimable),
            allLessonsCompleted: Boolean(certResult.allLessonsCompleted),
            allProjectsApproved: Boolean(certResult.allProjectsApproved),
            finalProjectRequired: Boolean(certResult.finalProjectRequired),
            finalProjectStatus: certResult.finalProjectStatus || "not_submitted",
            projectApprovals: Array.isArray(certResult.projectApprovals)
                ? certResult.projectApprovals.map((item) => ({
                    lessonId: item.lessonId,
                    lessonTitle: item.lessonTitle,
                    status: item.status,
                    reviewedAt: item.reviewedAt || null,
                    adminFeedback: item.adminFeedback || ""
                }))
                : [],
            adminFeedback: latestProject?.adminFeedback || latestProject?.reviewComment || "",
            reviewedAt: latestProject?.reviewedAt || null,
            issued: Boolean(certResult.issued),
            revoked: Boolean(certResult.revoked)
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to fetch certificate status" });
    }
});

app.post("/api/certificate/claim", async (req, res) => {
    try {
        const { userId, courseId } = req.body || {};
        if (!userId || !courseId) {
            return res.status(400).json({ success: false, message: "userId and courseId are required" });
        }

        const certResult = await ensureCertificateState({
            req,
            userId: String(userId),
            courseId: String(courseId),
            issueIfEligible: true
        });

        if (!certResult.certificate) {
            return res.status(409).json({
                success: false,
                message: "Certificate is locked. Complete all lessons and get all project submissions approved.",
                claimable: Boolean(certResult.claimable),
                allLessonsCompleted: Boolean(certResult.allLessonsCompleted),
                allProjectsApproved: Boolean(certResult.allProjectsApproved),
                projectApprovals: Array.isArray(certResult.projectApprovals)
                    ? certResult.projectApprovals.map((item) => ({
                        lessonId: item.lessonId,
                        lessonTitle: item.lessonTitle,
                        status: item.status,
                        reviewedAt: item.reviewedAt || null,
                        adminFeedback: item.adminFeedback || ""
                    }))
                    : []
            });
        }

        return res.json({
            success: true,
            certificate: {
                certificateId: certResult.certificate.certificateId,
                userName: certResult.certificate.userName,
                courseName: certResult.certificate.courseName,
                completionDate: certResult.certificate.completionDate,
                qrVerificationLink: certResult.certificate.qrVerificationLink
            },
            issued: Boolean(certResult.issued)
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to claim certificate" });
    }
});

app.get("/api/certificate/:userId/:courseId/download", async (req, res) => {
    try {
        const { userId, courseId } = req.params;
        const certResult = await ensureCertificateState({ req, userId, courseId, issueIfEligible: false });
        if (!certResult.certificate) {
            return res.status(404).json({ success: false, message: "Certificate not available yet" });
        }

        const cert = certResult.certificate;
        const completionDate = new Date(cert.completionDate || cert.issuedAt || Date.now());
        const displayDate = completionDate.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MindStep Certificate</title>
  <style>
    body { margin: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0b1020; color: #e6edf3; }
    .wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
    .card {
      width: min(980px, 96vw);
      background: linear-gradient(145deg, rgba(20,28,52,0.94), rgba(9,14,30,0.96));
      border: 1px solid rgba(97,140,255,0.35);
      border-radius: 24px;
      box-shadow: 0 20px 80px rgba(0,0,0,0.45), inset 0 0 0 1px rgba(255,255,255,0.05);
      padding: 42px;
      position: relative;
      overflow: hidden;
    }
    .card:before {
      content: "";
      position: absolute;
      inset: -120px;
      background: radial-gradient(circle at top right, rgba(56,189,248,0.2), transparent 45%),
                  radial-gradient(circle at bottom left, rgba(250,204,21,0.18), transparent 40%);
      pointer-events: none;
    }
    .brand { text-align: center; letter-spacing: 2px; font-size: 14px; color: #93c5fd; position: relative; }
    h1 { text-align: center; margin: 14px 0 8px; font-size: 44px; letter-spacing: 2px; position: relative; }
    h2 { text-align: center; margin: 0 0 26px; color: #cbd5e1; font-weight: 500; position: relative; }
    .line { height: 1px; background: linear-gradient(90deg, transparent, rgba(148,163,184,0.5), transparent); margin: 22px 0; }
    .text { text-align: center; font-size: 18px; color: #cbd5e1; position: relative; }
    .name { text-align: center; margin: 18px 0 12px; font-size: 36px; font-weight: 700; color: #f8fafc; position: relative; }
    .course { text-align: center; margin: 0 0 24px; font-size: 26px; color: #93c5fd; position: relative; }
    .meta { display: grid; gap: 8px; margin-top: 20px; color: #e2e8f0; position: relative; }
    .sig { margin-top: 28px; display: flex; justify-content: space-between; align-items: end; color: #94a3b8; position: relative; }
    .sig .auth { border-top: 1px solid rgba(148,163,184,0.5); padding-top: 8px; width: 220px; text-align: center; }
    .verify { font-size: 13px; color: #93c5fd; word-break: break-all; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="brand">MINDSTEP</div>
      <h1>CERTIFICATE OF COMPLETION</h1>
      <h2>This is to certify that</h2>
      <div class="name">${String(cert.userName || userId)}</div>
      <div class="text">has successfully completed the course</div>
      <div class="course">${String(cert.courseName || courseId)}</div>
      <div class="line"></div>
      <div class="meta">
        <div>Completion Date: ${displayDate}</div>
        <div>Certificate ID: ${String(cert.certificateId || "")}</div>
      </div>
      <div class="sig">
        <div class="auth">Authorized Signature</div>
        <div class="verify">Verify: ${String(cert.qrVerificationLink || "")}</div>
      </div>
    </div>
  </div>
</body>
</html>`;
        const safeCourse = String(cert.courseName || "course").replace(/[^a-z0-9]+/gi, "-").replace(/(^-|-$)/g, "");
        const fileName = `${safeCourse || "course"}-certificate-${cert.certificateId}.html`;

        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
        return res.send(html);
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to download certificate" });
    }
});

async function handleCertificateVerification(req, res) {
    try {
        const certificateId = String(req.params.certificateId || "").trim();
        if (!certificateId) return res.status(400).json({ success: false, message: "Invalid certificate id" });

        const cert = await Certificate.findOne({ certificateId }).lean();
        if (!cert) return res.status(404).json({ success: false, message: "Certificate not found" });

        return res.json({
            success: true,
            certificate: {
                certificateId: cert.certificateId,
                userId: cert.userId,
                userName: cert.userName,
                courseId: cert.courseId,
                courseName: cert.courseName,
                completionDate: cert.completionDate || cert.issuedAt,
                issuedAt: cert.issuedAt
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Verification failed" });
    }
}

app.get("/api/certificate-verify/:certificateId", handleCertificateVerification);
app.get("/api/certificate/verify/:certificateId", handleCertificateVerification);

app.get("/generate-certificate/:username", async (req, res) => {
    try {
        const username = String(req.params.username || "").trim();
        if (!username) return res.status(400).send("Invalid username");

        const user = await UserModel.findOne({ username }, "username").lean();
        if (!user) return res.status(404).send("User not found");

        const providedId = String(req.query.certificateId || "").trim().toUpperCase();
        const certificateId = /^MS-[A-Z0-9-]{6,40}$/.test(providedId)
            ? providedId
            : `MS-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;

        const completionDate = new Date();
        const displayDate = completionDate.toLocaleDateString("en-US", {
            day: "numeric",
            month: "long",
            year: "numeric"
        });
        const verificationLink = `https://mindstep.com/certificate/${encodeURIComponent(certificateId)}`;
        const learnerName = String(user.username || username);
        const nameSize = learnerName.length > 22 ? 40 : learnerName.length > 15 ? 48 : 56;

        const doc = new PDFDocument({
            size: "A4",
            layout: "landscape",
            margin: 0
        });

        const fileName = `MindStep-Certificate-${String(username).replace(/[^a-z0-9_-]+/gi, "_")}.pdf`;
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
        doc.pipe(res);

        const pageWidth = doc.page.width;
        const pageHeight = doc.page.height;
        const centerX = pageWidth / 2;

        // Paper background
        doc.rect(0, 0, pageWidth, pageHeight).fill("#f9f2e6");
        for (let y = 0; y < pageHeight; y += 6) {
            const alpha = y % 12 === 0 ? 0.06 : 0.03;
            doc.save();
            doc.strokeOpacity(alpha).lineWidth(0.4).strokeColor("#7c6b4a");
            doc.moveTo(0, y).lineTo(pageWidth, y).stroke();
            doc.restore();
        }

        // Luxury borders
        doc.lineWidth(6).strokeColor("#8b6a2f").rect(16, 16, pageWidth - 32, pageHeight - 32).stroke();
        doc.lineWidth(2).strokeColor("#d1b06b").rect(26, 26, pageWidth - 52, pageHeight - 52).stroke();
        doc.lineWidth(1).strokeColor("#8b6a2f").rect(42, 42, pageWidth - 84, pageHeight - 84).stroke();

        // Top heading
        doc.fillColor("#0f2f57")
            .font("Helvetica-Bold")
            .fontSize(42)
            .text("MINDSTEP", 0, 74, { align: "center", characterSpacing: 8 });
        doc.fillColor("#64748b")
            .font("Helvetica")
            .fontSize(14)
            .text("QUANTUM IDE", 0, 120, { align: "center", characterSpacing: 5 });
        doc.lineWidth(1.6).strokeColor("#ad8642").moveTo(154, 136).lineTo(pageWidth - 154, 136).stroke();

        // Certificate title
        doc.fillColor("#7a4a09")
            .font("Helvetica-Bold")
            .fontSize(44)
            .text("CERTIFICATE OF COMPLETION", 0, 164, { align: "center" });
        doc.fillColor("#334155")
            .font("Helvetica")
            .fontSize(22)
            .text("This is proudly presented to", 0, 230, { align: "center" });

        // Learner name
        doc.fillColor("#111827")
            .font("Helvetica-Bold")
            .fontSize(nameSize)
            .text(learnerName, 0, 270, { align: "center" });
        const underlineWidth = Math.min(430, 160 + learnerName.length * 12);
        doc.lineWidth(1.8).strokeColor("#9a6f2f")
            .moveTo(centerX - underlineWidth / 2, 350)
            .lineTo(centerX + underlineWidth / 2, 350)
            .stroke();

        doc.fillColor("#475569")
            .font("Helvetica")
            .fontSize(18)
            .text("for successfully completing the rigorous curriculum of", 0, 372, { align: "center" });
        doc.fillColor("#1e3a8a")
            .font("Helvetica-Bold")
            .fontSize(30)
            .text("FULL STACK WEB DEVELOPMENT", 0, 398, { align: "center" });

        // Bottom left (sign block)
        doc.fillColor("#0f2f57")
            .font("Helvetica-Bold")
            .fontSize(18)
            .text("MindStep Admin", 74, 488);
        doc.lineWidth(1.5).strokeColor("#8b6a2f").moveTo(74, 512).lineTo(230, 512).stroke();
        doc.fillColor("#64748b")
            .font("Helvetica")
            .fontSize(11)
            .text("Lead Instructor", 104, 518);

        // Official seal (govt-style look, custom brand)
        const sealX = centerX;
        const sealY = 505;
        for (let i = 0; i < 28; i++) {
            const angle = (Math.PI * 2 * i) / 28;
            const petalX = sealX + Math.cos(angle) * 42;
            const petalY = sealY + Math.sin(angle) * 42;
            doc.circle(petalX, petalY, 7).fill("#c98f1b");
        }
        doc.circle(sealX, sealY, 36).fill("#e0ad42");
        doc.circle(sealX, sealY, 30).fill("#f8e4b8");
        doc.lineWidth(1.2).strokeColor("#8b6a2f").circle(sealX, sealY, 30).stroke();
        doc.fillColor("#7c2d12")
            .font("Helvetica-Bold")
            .fontSize(7.5)
            .text("MINDSTEP", sealX - 26, sealY - 7, { width: 52, align: "center" });
        doc.fillColor("#7c2d12")
            .font("Helvetica")
            .fontSize(6.6)
            .text("OFFICIAL SEAL", sealX - 28, sealY + 4, { width: 56, align: "center" });

        // Bottom right (date + certificate id)
        const rightBlockX = pageWidth - 290;
        doc.fillColor("#0f172a")
            .font("Helvetica-Bold")
            .fontSize(22)
            .text(displayDate, rightBlockX, 486, { width: 228, align: "center" });
        doc.lineWidth(1.5).strokeColor("#8b6a2f").moveTo(rightBlockX + 12, 512).lineTo(rightBlockX + 216, 512).stroke();
        doc.fillColor("#64748b")
            .font("Helvetica")
            .fontSize(11)
            .text("Issue Date", rightBlockX, 518, { width: 228, align: "center" });
        doc.fillColor("#1d4ed8")
            .font("Helvetica")
            .fontSize(10)
            .text(`Certificate ID: ${certificateId}`, rightBlockX, 534, { width: 228, align: "center" });

        // Verification footer
        doc.fillColor("#64748b")
            .font("Helvetica")
            .fontSize(8.5)
            .text(verificationLink, 30, pageHeight - 16, { width: pageWidth - 60, align: "center" });

        doc.end();
    } catch (err) {
        console.error("Certificate generation failed:", err);
        if (!res.headersSent) {
            res.status(500).send("Certificate generation failed");
        }
    }
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
        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        );

        res.json({
            success: true,
            token,
            user: { ...user.toObject(), percentage: total ? Math.round((done / total) * 100) : 0 }
        });
    } catch { res.status(500).json({ success: false }); }
});

app.post("/api/complete", async (req, res) => {
    try {
        const { userId, lessonId } = req.body;
        if (!userId || !lessonId) return res.status(400).json({ success: false });
        const lessonObjectId = new mongoose.Types.ObjectId(lessonId);

        let lessonDoc = null;
        try {
            lessonDoc = await Lesson.findById(lessonObjectId).lean();
        } catch (e) { lessonDoc = null; }

        const lessonType = String(lessonDoc?.type || "").toLowerCase();
        const isProjectLesson = lessonType === "project";
        if (isProjectLesson) {
            const latestSubmission = await Project.findOne({
                userId,
                lessonId: lessonId.toString()
            }).sort({ createdAt: -1, updatedAt: -1 }).lean();

            const latestStatus = String(latestSubmission?.status || "not_submitted").toLowerCase();
            if (latestStatus !== "approved") {
                return res.status(409).json({
                    success: false,
                    pendingReview: true,
                    message: "Lesson will be marked complete only after admin approval.",
                    projectStatus: latestStatus,
                    adminFeedback: latestSubmission?.adminFeedback || latestSubmission?.reviewComment || ""
                });
            }
        }

        // Add to user's completed lessons array (id stored as string)
        await UserModel.findByIdAndUpdate(userId, { $addToSet: { completed_lessons: lessonId } });

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

        let certificate = null;
        let certificateClaimable = false;
        if (courseId) {
            const certResult = await ensureCertificateState({ req, userId, courseId, issueIfEligible: false });
            certificate = certResult.certificate || null;
            certificateClaimable = Boolean(certResult.claimable);
        }

        res.json({
            success: true,
            certificateAvailable: Boolean(certificate),
            certificateClaimable,
            certificate: certificate
                ? {
                    certificateId: certificate.certificateId,
                    completionDate: certificate.completionDate,
                    qrVerificationLink: certificate.qrVerificationLink
                }
                : null
        });
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
            Certificate.deleteMany({ userId }),
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

        const toUniqueStrings = (values) => {
            return [...new Set((values || [])
                .map(v => String(v || "").trim())
                .filter(Boolean))];
        };
        const toObjectIds = (values) => {
            return toUniqueStrings(values)
                .filter(id => mongoose.Types.ObjectId.isValid(id))
                .map(id => new mongoose.Types.ObjectId(id));
        };

        const userIds = toUniqueStrings(projects.map(p => p.userId));
        const lessonIds = toObjectIds(projects.map(p => normalizeObjectIdLike(p.lessonId)));
        const courseIds = toObjectIds(projects.map(p => normalizeObjectIdLike(p.courseId)));

        const [users, lessons, courses] = await Promise.all([
            userIds.length > 0
                ? UserModel.find({ _id: { $in: userIds } }, "username email").lean()
                : Promise.resolve([]),
            lessonIds.length > 0
                ? Lesson.find({ _id: { $in: lessonIds } }, "title").lean()
                : Promise.resolve([]),
            courseIds.length > 0
                ? Course.find({ _id: { $in: courseIds } }, "title slug").lean()
                : Promise.resolve([])
        ]);

        const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
        const lessonMap = Object.fromEntries(lessons.map(l => [l._id.toString(), l]));
        const courseMap = Object.fromEntries(courses.map(c => [c._id.toString(), c]));

        const results = projects.map(p => ({
            ...p,
            userId: userMap[p.userId] || null,
            lessonId: lessonMap[normalizeObjectIdLike(p.lessonId)] || p.lessonId || null,
            courseId: courseMap[normalizeObjectIdLike(p.courseId)] || p.courseId || null
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
        let { status, adminFeedback } = req.body || {};
        status = String(status || "").toLowerCase().trim();
        if (status === "request_changes") status = "rejected";
        if (!["pending", "approved", "rejected"].includes(status)) {
            return res.status(400).json({ success: false, message: "Invalid status" });
        }

        const project = await Project.findById(req.params.id);
        if (!project) return res.status(404).json({ success: false });
        const previousStatus = String(project.status || "").toLowerCase();
        const lessonForProject = mongoose.Types.ObjectId.isValid(project.lessonId)
            ? await Lesson.findById(new mongoose.Types.ObjectId(project.lessonId), "course_id").lean()
            : null;
        const resolvedProjectCourseId = String(lessonForProject?.course_id || project.courseId || "").trim();
        if (resolvedProjectCourseId && String(project.courseId || "").trim() !== resolvedProjectCourseId) {
            project.courseId = resolvedProjectCourseId;
        }

        const feedbackText = String(adminFeedback || "").trim();
        if ((status === "rejected") && !feedbackText) {
            return res.status(400).json({ success: false, message: "Admin feedback is required for rejected/changes requests" });
        }
        if (feedbackText) {
            project.adminFeedback = feedbackText;
            project.reviewComment = feedbackText;
        } else if (status === "approved") {
            project.adminFeedback = "";
            project.reviewComment = "";
        }

        project.status = status;
        project.reviewedAt = new Date();
        project.reviewedBy = "admin";

        if (status === "approved" && previousStatus !== "approved") {
            const user = await UserModel.findById(project.userId);
            if (user) {
                user.xp = (user.xp || 0) + (project.projectType === "planning" ? 50 : 100);
                if (!user.completed_lessons) user.completed_lessons = [];
                if (!user.completed_lessons.includes(project.lessonId)) user.completed_lessons.push(project.lessonId);
                await user.save();

                const lessonObjectId = new mongoose.Types.ObjectId(project.lessonId);
                await Completion.updateOne(
                    { user_id: project.userId, lesson_id: lessonObjectId },
                    { $setOnInsert: { user_id: project.userId, course_id: resolvedProjectCourseId || project.courseId, lesson_id: lessonObjectId, completed_at: new Date() } },
                    { upsert: true }
                );
            }
        } else if (status !== "approved" && previousStatus === "approved") {
            await Promise.all([
                UserModel.updateOne(
                    { _id: project.userId },
                    { $pull: { completed_lessons: project.lessonId } }
                ),
                Completion.deleteOne({
                    user_id: project.userId,
                    lesson_id: new mongoose.Types.ObjectId(project.lessonId)
                })
            ]);
        }

        await project.save();

        let certificate = null;
        let certificateIssued = false;
        let certificateRevoked = false;
        let certificateClaimable = false;
        if (resolvedProjectCourseId || project.courseId) {
            const certResult = await ensureCertificateState({
                req,
                userId: project.userId,
                courseId: resolvedProjectCourseId || project.courseId,
                issueIfEligible: false
            });
            certificate = certResult.certificate || null;
            certificateIssued = Boolean(certResult.issued);
            certificateRevoked = Boolean(certResult.revoked);
            certificateClaimable = Boolean(certResult.claimable);
        }

        res.json({
            success: true,
            project: {
                _id: project._id.toString(),
                status: project.status,
                adminFeedback: project.adminFeedback || "",
                reviewedAt: project.reviewedAt || null
            },
            certificateIssued,
            certificateRevoked,
            certificateClaimable,
            certificate: certificate
                ? {
                    certificateId: certificate.certificateId,
                    completionDate: certificate.completionDate,
                    qrVerificationLink: certificate.qrVerificationLink
                }
                : null
        });
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


// 
