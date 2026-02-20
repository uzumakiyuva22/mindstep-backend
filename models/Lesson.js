const mongoose = require("mongoose");

const lessonContentSchema = new mongoose.Schema(
  {
    intro: { type: String, default: "" },

    learningOutcomes: { type: [String], default: [] },

    deepExplanation: { type: [String], default: [] },

    conceptBreakdown: [
      {
        concept: { type: String, default: "" },
        explanation: { type: String, default: "" }
      }
    ],

    realWorldAnalogy: { type: [String], default: [] },

    example: {
      description: { type: String, default: "" },
      code: { type: String, default: "" }
    },

    stepByStepImplementation: { type: [String], default: [] },

    requiredFolderStructure: {
      rootFolderName: { type: String, default: "" },
      structure: { type: [String], default: [] }
    },

    exampleComponentCode: {
      description: { type: String, default: "" },
      code: { type: String, default: "" }
    },

    adminEvaluationCriteria: { type: [String], default: [] },

    projectUploadSection: {
      sectionTitle: { type: String, default: "" },
      uploadSteps: { type: [String], default: [] },
      allowedFiles: { type: [String], default: [] },
      notAllowed: { type: [String], default: [] },
      adminReviewNote: { type: String, default: "" }
    },

    userTask: {
      taskTitle: { type: String, default: "" },
      instructions: { type: [String], default: [] },
      submissionNote: { type: String, default: "" }
    },

    whyImportant: { type: [String], default: [] },

    commonMistakes: { type: [String], default: [] },

    practice: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },

    summary: { type: String, default: "" },

    nextLesson: { type: String, default: "" }
  },
  {
    _id: false,
    strict: false
  }
);

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

    estimatedTime: {
      type: String,
      default: ""
    },

    type: {
      type: String,
      default: ""
    },

    projectType: {
      type: String,
      default: ""
    },

    submission: {
      allowedFormats: { type: [String], default: [] },
      maxFileSizeMB: { type: Number },
      note: { type: String, default: "" }
    },

    tasks: {
      type: [mongoose.Schema.Types.Mixed],
      default: []
    },

    // 📄 Lesson PDF path
    pdf: {
      type: String,
      default: ""
    },

    created_at: {
      type: Date
    },

    // 📘 Structured lesson content
    lesson: {
      type: lessonContentSchema,
      default: () => ({})
    }
  },
  {
    timestamps: true
  }
);

// 🚀 Performance Index
LessonSchema.index({ course_id: 1, order: 1 });

module.exports = mongoose.model("Lesson", LessonSchema);
