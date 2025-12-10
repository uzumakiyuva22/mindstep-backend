const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const adminSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { versionKey: false });
module.exports = mongoose.model('Admin', adminSchema);
