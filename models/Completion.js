const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  user_id: String,
  course_id: { type: mongoose.Schema.Types.ObjectId, ref: "Course" },
  lesson_id: { type: mongoose.Schema.Types.ObjectId, ref: "Lesson" }
});

schema.index({ user_id: 1, lesson_id: 1 }, { unique: true });

module.exports = mongoose.model("Completion", schema);
