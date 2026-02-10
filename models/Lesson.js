const mongoose = require("mongoose");

const LessonSchema = new mongoose.Schema(
  {
    // 🏷 Lesson title
    title: {
      type: String,
      required: true,
      trim: true
    },

    // 🧾 Short description (used in lists)
    description: {
      type: String,
      default: ""
    },

    // 🔢 Order inside course
    order: {
      type: Number,
      default: 0,
      index: true
    },

    // 🔗 Course relation (String for compatibility)
    course_id: {
      type: String,
      required: true,
      index: true
    },

    // 🎥 Lesson video (YouTube / Vimeo / Drive)
    video: {
      type: String,
      trim: true,
      default: ""
    },

    // 📝 Lesson notes (HTML / Markdown)
    notes: {
      type: String,
      default: ""
    },

    // 📄 Lesson PDF path
    pdf: {
      type: String,
      default: ""
    },

    // 📘 Structured lesson content
    lesson: {
      intro: { type: String, default: "" },

      learningOutcomes: { type: [String], default: [] },

      deepExplanation: { type: [String], default: [] },

      conceptBreakdown: [
        {
          concept: { type: String, default: "" },
          explanation: { type: String, default: "" }
        }
      ],

      example: {
        description: { type: String, default: "" },
        code: { type: String, default: "" }
      },

      whyImportant: { type: [String], default: [] },

      commonMistakes: { type: [String], default: [] },

      practice: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      },

      summary: { type: String, default: "" },

      nextLesson: { type: String, default: "" }
    }
  },
  {
    timestamps: true
  }
);

// 🚀 Performance Index
LessonSchema.index({ course_id: 1, order: 1 });

module.exports = mongoose.model("Lesson", LessonSchema);
