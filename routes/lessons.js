const express = require("express");
const router = express.Router();
const Lesson = require("../models/Lesson");
const Task = require("../models/Task");

router.get("/:id/details", async (req, res) => {
  try {
    const lesson = await Lesson.findById(req.params.id).lean();
    if (!lesson) return res.status(404).json({ success: false, error: "Lesson not found" });
    const tasks = await Task.find({ lesson_id: lesson._id }).lean();
    res.json({ success: true, lesson, tasks });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: "Server error" }); }
});

module.exports = router;
