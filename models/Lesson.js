const mongoose = require("mongoose");

const lessonSchema = new mongoose.Schema({
  title: String,
  description: String,
  slug: String,
  order: Number,
  course_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true
  }
});

module.exports = mongoose.model("Lesson", lessonSchema);
