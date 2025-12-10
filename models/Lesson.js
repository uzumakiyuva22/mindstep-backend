const mongoose = require("mongoose");

const lessonSchema = new mongoose.Schema(
  {
    _id: mongoose.Schema.Types.ObjectId,
    course_id: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
    title: { type: String, required: true },
    section: String,
    order: Number,
    content: String,
    created_at: { type: Date, default: Date.now }
  },
  { versionKey: false }
);

module.exports = mongoose.model("Lesson", lessonSchema);
