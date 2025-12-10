const express = require("express");
const router = express.Router();
const Course = require("../models/Course");
const Lesson = require("../models/Lesson");
const Task = require("../models/Task");

// public courses summary
router.get("/public", async (req, res) => {
  try {
    const courses = await Course.find({}).lean();
    const results = [];
    for (const c of courses) {
      const lessons = await Lesson.find({ course_id: c._id }).lean();
      const totalTasks = await Task.countDocuments({ course_id: c._id });
      results.push({ course: c, lessonCount: lessons.length, totalTasks });
    }
    res.json({ success: true, results });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: "Server error" }); }
});

// lessons grouped for a course slug
router.get("/:slug/lessons", async (req, res) => {
  try {
    const slug = req.params.slug;
    const course = await Course.findOne({ slug }).lean();
    if (!course) return res.status(404).json({ success: false, error: "Course not found" });
    const lessons = await Lesson.find({ course_id: course._id }).sort({ order: 1 }).lean();
    const tasks = await Task.find({ course_id: course._id }).lean();
    const grouped = lessons.map(l => ({ ...l, tasks: tasks.filter(t => t.lesson_id === l._id) }));
    res.json({ success: true, course, lessons: grouped });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: "Server error" }); }
});

module.exports = router;
