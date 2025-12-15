// models/Task.js
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");

const taskSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  course_id: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
  lesson_id: { type: String, required: true }, // keep string if lessons use string ids
  title: { type: String, required: true },
  description: { type: String, default: "" },
  starterCode: { type: String, default: "" },
  language: { type: String, default: "javascript" },
  expectedOutput: { type: String, default: "" }
}, { versionKey: false });

module.exports = mongoose.model("Task", taskSchema);
