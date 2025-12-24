const mongoose = require("mongoose");

const TaskProgressSchema = new mongoose.Schema({
  user_id: String,
  task_id: String,
  lesson_id: String,
  passed: { type: Boolean, default: false }
});

module.exports = mongoose.model("TaskProgress", TaskProgressSchema);
