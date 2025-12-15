const mongoose = require("mongoose");

module.exports = mongoose.model(
  "Lesson",
  new mongoose.Schema({
    title: String,
    description: String,
    order: Number,
    course_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
      required: true
    }
  })
);
