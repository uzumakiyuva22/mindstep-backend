const mongoose = require("mongoose");

module.exports = mongoose.model(
  "Task",
  new mongoose.Schema({
    course_id: { type: mongoose.Schema.Types.ObjectId, ref: "Course" },
    lesson_id: { type: mongoose.Schema.Types.ObjectId, ref: "Lesson" },
    title: String,
    description: String,
    starterCode: String,
    language: String,
    expectedOutput: String
  })
);
