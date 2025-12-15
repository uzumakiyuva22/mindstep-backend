const mongoose = require("mongoose");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const Course = require("./models/Course");
const Lesson = require("./models/Lesson");
const Task = require("./models/Task");

// Define User model inline for seed
const User = mongoose.model("User", new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: String,
  email: String,
  password: String,
  image: String,
  percentage: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
}), "users");

// Define Admin model inline for seed
const Admin = mongoose.model("Admin", new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: String,
  password: String
}), "admins");

async function seed() {
  // Seed test users first
  const userCount = await User.countDocuments();
  if (userCount === 0) {
    const testUsers = [
      {
        username: "testuser",
        email: "test@mindstep.com",
        password: bcrypt.hashSync("password123", 10),
        image: null,
        percentage: 0
      },
      {
        username: "Team_Akatsuki_22",
        email: "akatsuki@mindstep.com",
        password: bcrypt.hashSync("password123", 10),
        image: null,
        percentage: 0
      }
    ];

    for (const user of testUsers) {
      await User.create(user);
      console.log("✔ Seeded user:", user.username);
    }
  }

  // Ensure an admin exists (always run)
  const adminCount = await Admin.countDocuments();
  if (adminCount === 0) {
    const adminPass = process.env.ADMIN_SECRET || "yuva22";
    await Admin.create({ username: "Uzumaki_Yuva", password: bcrypt.hashSync(adminPass, 10) });
    console.log("✔ Seeded admin: Uzumaki_Yuva");
  }

  const exists = await Course.countDocuments();
  if (exists > 0) {
    console.log("✔ Courses already exist – skip course seed");
    return;
  }

  const courses = [
    { slug: "html", title: "HTML", description: "Build semantic, accessible, and modern HTML structures." },
    { slug: "css", title: "CSS", description: "Master responsive layouts, gradients, and animations." },
    { slug: "javascript", title: "JavaScript", description: "Create interactive and dynamic web experiences." },
    { slug: "java", title: "Java Basics", description: "Develop backend systems and scalable applications." },
    { slug: "python", title: "Python Basics", description: "Automate tasks, analyze data, and build scripts." }
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

  
}

module.exports = seed;

// If run directly, connect to MongoDB, run seed, then exit.
if (require.main === module) {
  const MONGO = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/mindstep";
  mongoose.set("strictQuery", false);
  mongoose
    .connect(MONGO)
    .then(async () => {
      console.log("→ Connected to Mongo for seeding");
      try {
        await seed();
      } catch (err) {
        console.error("Seed error:", err);
        process.exitCode = 1;
      } finally {
        await mongoose.disconnect();
        console.log("→ Disconnected after seeding");
      }
    })
    .catch((err) => {
      console.error("Mongo connect failed for seed:", err);
      process.exit(1);
    });
}
