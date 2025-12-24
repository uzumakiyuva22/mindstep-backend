const mongoose = require("mongoose");

const TaskSchema = new mongoose.Schema({
  lesson_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Lesson",
    required: true
  },
  language: {
    type: String,
    enum: ["python", "java", "javascript", "html", "css"],
    required: true
  },
  title: String,
  description: String,
  starterCode: String,
  expectedOutput: String,
  order: Number
});

module.exports = mongoose.model("Task", TaskSchema);
