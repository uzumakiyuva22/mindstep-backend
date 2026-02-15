const mongoose = require("mongoose");

const IssueSchema = new mongoose.Schema(
  {
    courseId: {
      type: String,
      required: [true, "courseId is required"],
      trim: true,
      index: true,
    },
    lessonId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Lesson",
      required: [true, "lessonId is required"],
      index: true,
    },
    userId: {
      type: String,
      required: [true, "userId is required"],
      trim: true,
      index: true,
    },
    errorMessage: {
      type: String,
      required: [true, "errorMessage is required"],
      trim: true,
      minlength: [3, "errorMessage must be at least 3 characters"],
      maxlength: [300, "errorMessage must be at most 300 characters"],
    },
    description: {
      type: String,
      required: [true, "description is required"],
      trim: true,
      minlength: [10, "description must be at least 10 characters"],
      maxlength: [5000, "description must be at most 5000 characters"],
    },
    screenshot: {
      type: String,
      default: "",
      trim: true,
    },
    status: {
      type: String,
      enum: ["Pending", "Resolved"],
      default: "Pending",
      index: true,
    },
    adminReply: {
      type: String,
      default: "",
      trim: true,
      maxlength: [2000, "adminReply must be at most 2000 characters"],
    },
    repliedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Issue || mongoose.model("Issue", IssueSchema);
