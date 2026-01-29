const mongoose = require('mongoose');

const ProjectSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  courseId: {
    type: String,  // Course ID stored as string
    required: true
  },
  originalName: {
    type: String,  // User upload panna file name (e.g., myproject.zip)
    required: true
  },
  storedName: {
    type: String,  // Server la save aana unique name
    required: true
  },
  filePath: {
    type: String,  // Path to the file
    required: true
  },
  submittedAt: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['submitted', 'approved', 'rejected'],
    default: 'submitted'
  }
});

module.exports = mongoose.model('Project', ProjectSchema);