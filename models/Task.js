const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const schema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  course_id: { type: String, required: true },
  lesson_id: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, default: '' },
  starterCode: { type: String, default: '' },
  language: { type: String, default: 'javascript' },
  expectedOutput: { type: String, default: '' }
}, { versionKey: false });
module.exports = mongoose.model('Task', schema);
