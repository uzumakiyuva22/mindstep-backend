const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const courseSchema = new Schema({
  slug: { type: String, unique: true, required: true },
  title: String,
  description: String,
  fullDescription: String,
  image: String,
  difficulty: { type: String, default: "Beginner" },
  order: Number,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Course", courseSchema);
