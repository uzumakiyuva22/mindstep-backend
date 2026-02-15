const mongoose = require("mongoose");

const TaskProgressSchema = new mongoose.Schema({
  userId: { type: String, index: true },
  taskId: { type: String, index: true },
  status: { type: String, enum: ["pending", "completed"], default: "pending" },
  attempts: { type: Number, default: 0 },
  lastAttemptAt: { type: Date, default: Date.now },
  completedAt: Date,

  // Backward-compatible fields
  user_id: String,
  lesson_id: mongoose.Schema.Types.ObjectId,
  task_id: mongoose.Schema.Types.ObjectId,
  passed: { type: Boolean, default: false },
  output: String,
  submittedAt: Date
});

TaskProgressSchema.index({ user_id: 1, task_id: 1 }, { unique: true });
TaskProgressSchema.index(
  { userId: 1, taskId: 1 },
  { unique: true, partialFilterExpression: { userId: { $type: "string" }, taskId: { $type: "string" } } }
);

module.exports = mongoose.model("TaskProgress", TaskProgressSchema);
