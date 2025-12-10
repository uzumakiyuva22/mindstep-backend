const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const schema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  user_id: { type: String, required: true },
  course_id: { type: String, required: true },
  lesson_id: { type: String, required: true },
  task_id: { type: String, required: true }
}, { versionKey: false });
schema.index({ user_id:1, task_id:1 }, { unique:true });
module.exports = mongoose.model('Completion', schema);
