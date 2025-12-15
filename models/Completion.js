const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");

const completionSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  user_id: { type: String, required: true },
  course_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true
  },
  lesson_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Lesson",
    required: true
  }
});

completionSchema.index(
  { user_id: 1, lesson_id: 1 },
  { unique: true }
);

module.exports = mongoose.model("Completion", completionSchema);
