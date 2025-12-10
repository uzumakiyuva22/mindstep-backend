const mongoose = require("mongoose");

const taskSchema = new mongoose.Schema(
  {
    _id: mongoose.Schema.Types.ObjectId,
    course_id: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
    lesson_id: { type: mongoose.Schema.Types.ObjectId, ref: "Lesson", required: true },
    title: { type: String, required: true },
    description: String,
    starterCode: String,
    language: { type: String, enum: ["java", "python", "javascript", "html", "css"], required: true },
    expectedOutput: String,
    created_at: { type: Date, default: Date.now }
  },
  { versionKey: false }
);

module.exports = mongoose.model("Task", taskSchema);
