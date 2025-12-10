const express = require("express");
const router = express.Router();
const Course = require("../models/Course");
const Task = require("../models/Task");
const Completion = require("../models/Completion");

router.get("/:slug/:userId", async (req, res) => {
  try {
    const { slug, userId } = req.params;
    const course = await Course.findOne({ slug }).lean();
    if (!course) return res.status(404).json({ success: false, error: "Course not found" });

    const totalTasks = await Task.countDocuments({ course_id: course._id });
    const done = await Completion.countDocuments({ user_id: userId, course_id: course._id });

    const percent = totalTasks === 0 ? 0 : Math.round((done / totalTasks) * 100);
    res.json({ success: true, courseId: course._id, totalTasks, done, percent });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: "Server error" }); }
});

module.exports = router;
