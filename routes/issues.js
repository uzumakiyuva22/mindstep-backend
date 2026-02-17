const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const mongoose = require("mongoose");
const Issue = require("../models/Issue");
const auth = require("../middleware/auth");

const router = express.Router();

// 1. Setup Upload Directory
const ISSUES_UPLOAD_DIR = path.join(__dirname, "..", "public", "uploads", "issues");
if (!fs.existsSync(ISSUES_UPLOAD_DIR)) {
  fs.mkdirSync(ISSUES_UPLOAD_DIR, { recursive: true });
}

// 2. Multer Configuration
const screenshotStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, ISSUES_UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
    cb(null, `issue-${Date.now()}-${safeName}`);
  },
});

const uploadIssueScreenshot = multer({
  storage: screenshotStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB Limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith("image/")) return cb(null, true);
    cb(new Error("Only image files are allowed for screenshot"));
  },
});

// 3. Helper Functions
function isValidObjectId(value) {
  return mongoose.Types.ObjectId.isValid(value);
}

function buildScreenshotPath(file) {
  if (!file) return "";
  return `/uploads/issues/${file.filename}`;
}

// 4. Admin Middleware
function requireAdmin(req, res, next) {
  const adminSecret = req.headers.admin_secret;
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

// ================= ROUTES =================

// POST /api/issues (User reports a bug)
router.post("/", auth, uploadIssueScreenshot.single("screenshot"), async (req, res) => {
  try {
    const { courseId, lessonId, errorMessage, description } = req.body;

    if (!courseId || !lessonId || !errorMessage || !description) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const newIssue = new Issue({
      courseId: String(courseId).trim(),
      lessonId,
      userId: req.user.id,
      errorMessage: String(errorMessage).trim(),
      description: String(description).trim(),
      screenshot: buildScreenshotPath(req.file),
    });

    await newIssue.save();
    return res.status(201).json({ success: true, issue: newIssue });
  } catch (err) {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ success: false, message: "Screenshot must be <= 5MB" });
      }
      return res.status(400).json({ success: false, message: err.message });
    }

    if (err && err.message === "Only image files are allowed for screenshot") {
      return res.status(400).json({ success: false, message: err.message });
    }

    if (err.name === "ValidationError") {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: Object.values(err.errors).map((e) => e.message),
      });
    }

    console.error("Issue Create Error:", err);
    return res.status(500).json({ success: false, message: "Failed to create issue" });
  }
});

// GET /api/issues (Admin lists issues)
router.get("/", requireAdmin, async (req, res) => {
  try {
    const { status, courseId, lessonId, userId, page = 1, limit = 20 } = req.query;
    const query = {};

    if (status) {
      const allowed = ["Pending", "Resolved"];
      if (!allowed.includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid status filter" });
      }
      query.status = status;
    }

    if (courseId) query.courseId = String(courseId).trim();

    if (lessonId) query.lessonId = String(lessonId).trim();

    if (userId) query.userId = String(userId).trim();

    const safePage = Math.max(parseInt(page, 10) || 1, 1);
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);

    // ✅ FIXED: Population logic ensures user details appear in Admin Dashboard
    const [issues, total] = await Promise.all([
      Issue.find(query)
        .populate("userId", "username email") // Fetch username & email
        .sort({ createdAt: -1 })
        .skip((safePage - 1) * safeLimit)
        .limit(safeLimit),
      Issue.countDocuments(query),
    ]);

    return res.json({
      success: true,
      data: issues,
      pagination: {
        page: safePage,
        limit: safeLimit,
        total,
        totalPages: Math.ceil(total / safeLimit),
      },
    });
  } catch (err) {
    console.error("Issue Fetch Error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch issues" });
  }
});

// PATCH /api/issues/:id (Admin updates status + reply)
router.patch("/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminReply } = req.body;

    if (!isValidObjectId(id)) {
      return res.status(400).json({ success: false, message: "Invalid issue id" });
    }

    if (status === undefined && adminReply === undefined) {
      return res.status(400).json({ success: false, message: "Provide status or adminReply" });
    }

    const update = {};

    if (status !== undefined) {
      const allowed = ["Pending", "Resolved"];
      if (!allowed.includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid status value" });
      }
      update.status = status;
    }

    if (adminReply !== undefined) {
      if (typeof adminReply !== "string" || !adminReply.trim()) {
        return res.status(400).json({ success: false, message: "adminReply must be a non-empty string" });
      }
      update.adminReply = adminReply.trim();
      update.repliedAt = new Date();
    }

    const issue = await Issue.findByIdAndUpdate(id, update, { new: true, runValidators: true });

    if (!issue) {
      return res.status(404).json({ success: false, message: "Issue not found" });
    }

    return res.json({ success: true, issue });
  } catch (err) {
    if (err.name === "ValidationError") {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: Object.values(err.errors).map((e) => e.message),
      });
    }

    console.error("Issue Update Error:", err);
    return res.status(500).json({ success: false, message: "Failed to update issue" });
  }
});

module.exports = router;
