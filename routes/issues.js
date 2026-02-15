const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const mongoose = require("mongoose");
const Issue = require("../models/Issue");

const router = express.Router();
const ISSUES_UPLOAD_DIR = path.join(__dirname, "..", "public", "uploads", "issues");
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

if (!fs.existsSync(ISSUES_UPLOAD_DIR)) {
  fs.mkdirSync(ISSUES_UPLOAD_DIR, { recursive: true });
}

const screenshotStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, ISSUES_UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
    cb(null, `issue-${Date.now()}-${safeName}`);
  },
});

const uploadIssueScreenshot = multer({
  storage: screenshotStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith("image/")) return cb(null, true);
    cb(new Error("Only image files are allowed for screenshot"));
  },
});

function isValidObjectId(value) {
  return mongoose.Types.ObjectId.isValid(value);
}

function buildScreenshotPath(file) {
  if (!file) return "";
  return `/uploads/issues/${file.filename}`;
}

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  const token = authHeader.split(" ")[1];
  if (!token || token !== ADMIN_SECRET) {
    return res.status(403).json({ success: false, message: "Forbidden" });
  }
  return next();
}

// POST /api/issues (user reports bug)
router.post("/", uploadIssueScreenshot.single("screenshot"), async (req, res) => {
  try {
    const { courseId, lessonId, userId, errorMessage, description } = req.body;

    if (!courseId || !lessonId || !userId || !errorMessage || !description) {
      return res.status(400).json({
        success: false,
        message: "courseId, lessonId, userId, errorMessage and description are required",
      });
    }

    if (!isValidObjectId(lessonId)) {
      return res.status(400).json({ success: false, message: "Invalid lessonId" });
    }

    const issue = await Issue.create({
      courseId: String(courseId).trim(),
      lessonId,
      userId: String(userId).trim(),
      errorMessage: String(errorMessage).trim(),
      description: String(description).trim(),
      screenshot: buildScreenshotPath(req.file),
    });

    return res.status(201).json({ success: true, issue });
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

    return res.status(500).json({ success: false, message: "Failed to create issue" });
  }
});

// GET /api/issues (admin list)
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

    if (lessonId) {
      if (!isValidObjectId(lessonId)) {
        return res.status(400).json({ success: false, message: "Invalid lessonId filter" });
      }
      query.lessonId = lessonId;
    }

    if (userId) query.userId = String(userId).trim();

    const safePage = Math.max(parseInt(page, 10) || 1, 1);
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);

    const [issues, total] = await Promise.all([
      Issue.find(query)
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
    return res.status(500).json({ success: false, message: "Failed to fetch issues" });
  }
});

// PATCH /api/issues/:id (admin update status + reply)
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

    return res.status(500).json({ success: false, message: "Failed to update issue" });
  }
});

module.exports = router;
