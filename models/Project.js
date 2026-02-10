// models/Project.js

const mongoose = require("mongoose"); // ✅ REQUIRED

const projectSchema = new mongoose.Schema(
  {
    // 🔑 User ID (UUID stored as String)
    userId: {
      type: String,
      ref: "User",
      required: true,
      index: true
    },

    // 📘 Lesson linked to this submission
    lessonId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Lesson",
      required: true,
      index: true
    },

    // 📚 Course ID (string for flexibility)
    courseId: {
      type: String,
      required: true,
      index: true
    },

    // 🧠 Project category
    // planning → DOCX/PDF plan
    // code → actual project source code
    projectType: {
      type: String,
      enum: ["planning", "code"],
      default: "planning",
      required: true
    },

    // 📄 Original uploaded filename
    originalName: {
      type: String,
      required: true,
      trim: true
    },

    // 💾 Stored filename on server
    storedName: {
      type: String,
      required: true
    },

    // 📂 Public file path
    filePath: {
      type: String,
      required: true
    },

    // 📏 File size in bytes
    fileSize: {
      type: Number,
      required: true,
      min: 1
    },

    // 🏷️ Review status
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
      index: true
    }
  },
  {
    timestamps: true // ✅ adds createdAt & updatedAt
  }
);

module.exports = mongoose.model("Project", projectSchema);
