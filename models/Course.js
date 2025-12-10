const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const schema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  slug: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  description: { type: String, default: '' }
}, { versionKey: false });
module.exports = mongoose.model('Course', schema);
