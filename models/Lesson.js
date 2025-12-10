const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const schema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  course_id: { type: String, required: true },
  title: { type: String, required: true },
  section: { type: String, required: true },
  order: { type: Number, default: 0 },
  content: { type: String, default: '' }
}, { versionKey: false });
module.exports = mongoose.model('Lesson', schema);
