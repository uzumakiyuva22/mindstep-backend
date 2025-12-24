const mongoose = require("mongoose");

const LessonSchema = new mongoose.Schema({
  title: String,
  description: String,
  order: Number,
  course_id: String,

  lesson: {
    learningOutcomes: [String],
    intro: String,
    deepExplanation: [String],
    conceptBreakdown: [
      {
        concept: String,
        explanation: String
      }
    ],
    example: {
      description: String,
      code: String
    },
    whyImportant: [String],
    commonMistakes: [String],
    practice: Object,
    summary: String,
    nextLesson: String
  },

  created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Lesson", LessonSchema);
