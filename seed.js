const Course = require("./models/Course");
const Lesson = require("./models/Lesson");
const Task = require("./models/Task");

module.exports = async function seed() {
  const exists = await Course.countDocuments();
  if (exists > 0) {
    console.log("✔ Courses already exist – skip seed");
    return;
  }

  const courses = [
    { slug: "java", title: "Java Basics", description: "Core Java basics" },
    { slug: "python", title: "Python Basics", description: "Python from zero" }
  ];

  for (const c of courses) {
    const course = await Course.create(c);

    const sections = ["Introduction", "Basic", "Practice", "Project"];

    for (let i = 0; i < sections.length; i++) {
      const lesson = await Lesson.create({
        title: `${sections[i]} - ${course.title}`,
        description: `${sections[i]} content`,
        order: i + 1,
        course_id: course._id
      });

      await Task.create({
        course_id: course._id,
        lesson_id: lesson._id,
        title: "Sample Task",
        description: "Print Hello",
        starterCode: `System.out.println("Hello");`,
        language: "java",
        expectedOutput: "Hello"
      });
    }

    console.log("✔ Seeded:", course.title);
  }
};
