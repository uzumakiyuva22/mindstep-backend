const mongoose = require("mongoose");

const courseSchema = new mongoose.Schema(
  {
    _id: mongoose.Schema.Types.ObjectId,
    slug: { type: String, unique: true, required: true },
    title: { type: String, required: true },
    description: String,
    created_at: { type: Date, default: Date.now }
  },
  { versionKey: false }
);

module.exports = mongoose.model("Course", courseSchema);
