const mongoose = require("mongoose");

module.exports = mongoose.model(
  "Course",
  new mongoose.Schema({
    slug: { type: String, unique: true },
    title: String,
    description: String
  })
);
