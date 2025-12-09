/**
 * MindStep Backend — Pre-seeded Courses (HTML, CSS, JavaScript, Java, Python)
 * Advanced Course Builder (Option 2) + Pre-populated course data
 *
 * Required env:
 *  - MONGO_URI
 *  - CLOUDINARY_URL  OR (CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET)
 * Optional:
 *  - ADMIN_SECRET
 *  - JDOODLE_CLIENT_ID
 *  - JDOODLE_CLIENT_SECRET
 *
 * Node 18+ recommended
 */

require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const cloudinary = require("cloudinary").v2;
const fetch = global.fetch || require("node-fetch");

// ---------- CONFIG ----------
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");
const TEMP_DIR = path.join(__dirname, "temp");
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// ---------- ENV checks ----------
if (!process.env.MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI missing in environment.");
  process.exit(1);
}
if (
  !process.env.CLOUDINARY_URL &&
  !(
    process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
  )
) {
  console.error("❌ ERROR: Cloudinary credentials missing.");
  process.exit(1);
}

// Cloudinary config
if (process.env.CLOUDINARY_URL) {
  cloudinary.config({ cloudinary_url: process.env.CLOUDINARY_URL, secure: true });
} else {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true,
  });
}

// JDoodle (optional)
const JD_ID = process.env.JDOODLE_CLIENT_ID || null;
const JD_SECRET = process.env.JDOODLE_CLIENT_SECRET || null;

// ---------- MONGODB ----------
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✔ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err && err.message ? err.message : err);
    process.exit(1);
  });

// ---------- EXPRESS ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
const upload = multer({ dest: TEMP_DIR });

// ---------- HELPERS ----------
const safeUnlink = (fp) => { try { if (fp && fs.existsSync(fp)) fs.unlinkSync(fp); } catch {} };

// run code: JDoodle first then piston
async function runCodeRemote(language, script) {
  // Try JDoodle if creds present
  try {
    if (JD_ID && JD_SECRET) {
      const r = await fetch("https://api.jdoodle.com/v1/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          clientId: JD_ID,
          clientSecret: JD_SECRET,
          script,
          language: language === "python" ? "python3" : (language === "javascript" ? "nodejs" : language),
          versionIndex: "0"
        })
      });
      const j = await r.json();
      if (j.output) return String(j.output).trim();
    }
  } catch (e) {
    console.warn("JDoodle error (continuing to Piston):", e && e.message ? e.message : e);
  }

  // Piston fallback
  try {
    const files = [{ name: language === "java" ? "Main.java" : (language === "python" ? "script.py" : "script.js"), content: script }];
    const resp = await fetch("https://emkc.org/api/v2/piston/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language: language, version: "latest", files })
    });
    const data = await resp.json();
    const out = data.run?.stdout || data.run?.output || data.run?.stderr || "";
    return String(out).trim();
  } catch (e) {
    console.error("Piston error:", e && e.message ? e.message : e);
    return "ERROR";
  }
}

// ---------- SCHEMAS ----------
const userSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  image: { type: String, default: null },
}, { versionKey: false });
const User = mongoose.model("User", userSchema);

const adminSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { versionKey: false });
const Admin = mongoose.model("Admin", adminSchema);

const courseSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  slug: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  description: { type: String, default: "" },
}, { versionKey: false });
const Course = mongoose.model("Course", courseSchema);

const lessonSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  course_id: { type: String, required: true },
  title: { type: String, required: true },
  section: { type: String, required: true }, // Introduction | Basic | Practice | Project
  order: { type: Number, default: 0 },
  content: { type: String, default: "" }
}, { versionKey: false });
const Lesson = mongoose.model("Lesson", lessonSchema);

const taskSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  course_id: { type: String, required: true },
  lesson_id: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, default: "" },
  starterCode: { type: String, default: "" },
  language: { type: String, default: "javascript" }, // html/css/javascript/python/java
  expectedOutput: { type: String, default: "" } // simple trimmed expected output (string)
}, { versionKey: false });
const Task = mongoose.model("Task", taskSchema);

const completionSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  user_id: { type: String, required: true },
  course_id: { type: String, required: true },
  lesson_id: { type: String, required: true },
  task_id: { type: String, required: true }
}, { versionKey: false });
completionSchema.index({ user_id: 1, task_id: 1 }, { unique: true });
const Completion = mongoose.model("Completion", completionSchema);

// ---------- DEFAULT ADMIN ----------
(async () => {
  try {
    const def = "Uzumaki_Yuva";
    const a = await Admin.findOne({ username: def }).lean();
    if (!a) {
      await Admin.create({ username: def, password: bcrypt.hashSync("yuva22", 10) });
      console.log("✔ Default admin created");
    } else {
      console.log("✔ Default admin exists");
    }
  } catch (e) {
    console.error("Admin init error:", e && e.message ? e.message : e);
  }
})();

const ADMIN_SECRET = process.env.ADMIN_SECRET || "mindstep_admin_secret";

// ---------- MIDDLEWARE ----------
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (!token || token !== ADMIN_SECRET) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// ---------- ROUTES: Auth ----------
app.post("/api/signup", upload.single("image"), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success: false, error: "Missing fields" });
    const exists = await User.findOne({ $or: [{ username }, { email }] }).lean();
    if (exists) return res.status(409).json({ success: false, error: "User exists" });

    let imageUrl = null;
    if (req.file) {
      try {
        const uploaded = await cloudinary.uploader.upload(req.file.path, { folder: "mindstep_users" });
        imageUrl = uploaded.secure_url || uploaded.url;
      } catch (e) { console.error("Cloudinary upload error:", e && e.message ? e.message : e); }
      safeUnlink(req.file.path);
    }

    const user = await User.create({ username, email, password: bcrypt.hashSync(password, 10), image: imageUrl });
    res.json({ success: true, user: { _id: user._id, username: user.username, email: user.email, image: user.image } });
  } catch (e) {
    console.error("Signup error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ success: false, error: "Missing fields" });
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user) return res.status(401).json({ success: false, error: "Invalid credentials" });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, error: "Invalid credentials" });
    res.json({ success: true, user: { _id: user._id, username: user.username, email: user.email, image: user.image }});
  } catch (e) {
    console.error("Login error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ---------- ADMIN: create course/lesson/task ----------
app.post("/api/admin/course", requireAdmin, async (req, res) => {
  try {
    const { slug, title, description } = req.body;
    if (!slug || !title) return res.status(400).json({ error: "Missing fields" });
    const exists = await Course.findOne({ slug }).lean();
    if (exists) return res.status(409).json({ error: "Course exists" });
    const c = await Course.create({ slug, title, description });
    res.json({ success: true, course: c });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/admin/lesson/:courseId", requireAdmin, async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const { title, section, order, content } = req.body;
    if (!title || !section) return res.status(400).json({ error: "Missing fields" });
    const l = await Lesson.create({ course_id: courseId, title, section, order: order || 0, content: content || "" });
    res.json({ success: true, lesson: l });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/admin/task/:lessonId/:courseId", requireAdmin, async (req, res) => {
  try {
    const { lessonId, courseId } = req.params;
    const { title, description, starterCode, language, expectedOutput } = req.body;
    if (!title) return res.status(400).json({ error: "Missing title" });
    const t = await Task.create({ lesson_id: lessonId, course_id: courseId, title, description: description || "", starterCode: starterCode || "", language: language || "python", expectedOutput: expectedOutput || "" });
    res.json({ success: true, task: t });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ---------- PUBLIC: get courses summary ----------
app.get("/api/public/courses", async (req, res) => {
  try {
    const courses = await Course.find({}).lean();
    const results = [];
    for (const c of courses) {
      const lessons = await Lesson.find({ course_id: c._id }).lean();
      const totalTasks = await Task.countDocuments({ course_id: c._id });
      results.push({ course: c, lessonCount: lessons.length, totalTasks });
    }
    res.json({ success: true, results });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ---------- PUBLIC: get course lessons grouped ----------
app.get("/api/course/:slug/lessons", async (req, res) => {
  try {
    const slug = req.params.slug;
    const c = await Course.findOne({ slug }).lean();
    if (!c) return res.status(404).json({ success: false, error: "Not found" });
    const lessons = await Lesson.find({ course_id: c._id }).sort({ order: 1 }).lean();
    const tasks = await Task.find({ course_id: c._id }).lean();
    const grouped = {};
    lessons.forEach(l => grouped[l._id] = { ...l, tasks: [] });
    tasks.forEach(t => { if (grouped[t.lesson_id]) grouped[t.lesson_id].tasks.push(t); });
    res.json({ success: true, course: c, lessons: Object.values(grouped) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ---------- GET lesson + tasks ----------
app.get("/api/lesson/:id", async (req, res) => {
  try {
    const lesson = await Lesson.findById(req.params.id).lean();
    if (!lesson) return res.status(404).json({ success: false, error: "Lesson not found" });
    const tasks = await Task.find({ lesson_id: lesson._id }).lean();
    res.json({ success: true, lesson, tasks });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ---------- TASK CHECK: run code and check expectedOutput ----------
app.post("/api/task/check", async (req, res) => {
  try {
    const { userId, courseId, lessonId, taskId, language, code } = req.body;
    if (!userId || !taskId) return res.status(400).json({ success: false, error: "Missing fields" });

    const task = await Task.findById(taskId).lean();
    if (!task) return res.status(404).json({ success: false, error: "Task not found" });

    // run code
    const out = await runCodeRemote(language || task.language || "python", code || task.starterCode || "");

    // simple exact-match trimmed comparison
    const passed = String(out).trim() === String(task.expectedOutput || "").trim();

    if (passed) {
      // upsert completion
      await Completion.updateOne(
        { user_id: userId, task_id: taskId },
        { $setOnInsert: { _id: uuidv4(), user_id: userId, task_id: taskId, course_id: courseId, lesson_id: lessonId } },
        { upsert: true }
      );
    }

    res.json({ success: true, passed, output: out });
  } catch (e) {
    console.error("task.check error:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ---------- USER COURSE PROGRESS ----------
app.get("/api/course/:slug/progress/:userId", async (req, res) => {
  try {
    const { slug, userId } = req.params;
    const course = await Course.findOne({ slug }).lean();
    if (!course) return res.status(404).json({ success: false, error: "Course not found" });

    const totalTasks = await Task.countDocuments({ course_id: course._id });
    const done = await Completion.countDocuments({ user_id: userId, course_id: course._id });

    const percent = totalTasks === 0 ? 0 : Math.round((done / totalTasks) * 100);
    res.json({ success: true, courseId: course._id, totalTasks, done, percent });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: "Server error" }); }
});

// ---------- SERVE FRONTEND ----------
app.get("/", (req, res) => {
  const file = path.join(PUBLIC_DIR, "LoginPage.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  res.send("<h3>MindStep backend</h3><p>Place frontend files in /public</p>");
});

// ---------- SEED DEFAULT COURSES / LESSONS / TASKS ----------
async function seedCoursesIfMissing() {
  try {
    const existing = await Course.countDocuments({});
    if (existing > 0) {
      console.log("Courses exist — skipping seeding");
      return;
    }

    console.log("Seeding default courses and lessons...");

    // Helper to create course + lessons + tasks
    async function createCourseWithContent(slug, title, description, template) {
      const course = await Course.create({ slug, title, description });
      for (const [index, section] of ["Introduction", "Basic", "Practice", "Project"].entries()) {
        // create a lesson for this section
        const lesson = await Lesson.create({ course_id: course._id, title: `${section} - ${title}`, section, order: index + 1, content: `${section} content for ${title}` });
        // create tasks for lesson (3 tasks per section -> 12 tasks per course)
        for (let t = 0; t < (template.tasksPerSection || 3); t++) {
          const taskIndex = index * (template.tasksPerSection || 3) + (t + 1);
          const tk = template.taskFactory(section, taskIndex);
          await Task.create({
            course_id: course._id,
            lesson_id: lesson._id,
            title: tk.title,
            description: tk.description,
            starterCode: tk.starterCode,
            language: tk.language,
            expectedOutput: tk.expectedOutput
          });
        }
      }
      console.log(`Seeded course: ${title}`);
    }

    // HTML course template
    await createCourseWithContent("html", "HTML Basics", "Learn semantic HTML and elements", {
      tasksPerSection: 3,
      taskFactory: (section, idx) => {
        // simple tasks with expectedOutput demonstration (we run HTML via JS engine? For HTML tasks, we will treat expectedOutput as a snippet string value to compare — frontend can run in iframe)
        if (section === "Introduction") {
          return { title: `HTML Intro Task ${idx}`, description: "Write a basic H1", starterCode: `<h1>Hello HTML</h1>`, language: "html", expectedOutput: "<h1>Hello HTML</h1>" };
        }
        if (section === "Basic") {
          return { title: `HTML Basic Task ${idx}`, description: "Create a paragraph", starterCode: `<p>Paragraph</p>`, language: "html", expectedOutput: "<p>Paragraph</p>" };
        }
        if (section === "Practice") {
          return { title: `HTML Practice Task ${idx}`, description: "Add an anchor", starterCode: `<a href='#'>Link</a>`, language: "html", expectedOutput: `<a href="#">Link</a>` };
        }
        return { title: `HTML Project Task ${idx}`, description: "Small page", starterCode: `<!doctype html><html><body><h1>Hi</h1></body></html>`, language: "html", expectedOutput: "<h1>Hi</h1>" };
      }
    });

    // CSS course template
    await createCourseWithContent("css", "CSS Styling", "Learn CSS basics & animations", {
      tasksPerSection: 3,
      taskFactory: (section, idx) => {
        if (section === "Introduction") {
          return { title: `CSS Intro ${idx}`, description: "Write CSS to set body background", starterCode: `body{background-color: lightblue;}`, language: "css", expectedOutput: "background-color: lightblue;" };
        }
        if (section === "Basic") {
          return { title: `CSS Basic ${idx}`, description: "Set text color", starterCode: `p{color: red;}`, language: "css", expectedOutput: "color: red;" };
        }
        if (section === "Practice") {
          return { title: `CSS Practice ${idx}`, description: "Create a rounded button", starterCode: `.btn{border-radius:8px;}`, language: "css", expectedOutput: "border-radius:8px;" };
        }
        return { title: `CSS Project ${idx}`, description: "Make a card style", starterCode: `.card{box-shadow:0 2px 8px rgba(0,0,0,.2);}`, language: "css", expectedOutput: "box-shadow:0 2px 8px rgba(0,0,0,.2);" };
      }
    });

    // JavaScript course template
    await createCourseWithContent("javascript", "JavaScript Essentials", "Learn JS basics and DOM", {
      tasksPerSection: 3,
      taskFactory: (section, idx) => {
        if (section === "Introduction") {
          return { title: `JS Intro ${idx}`, description: "Console log Hello", starterCode: `console.log("Hello JS")`, language: "javascript", expectedOutput: "Hello JS" };
        }
        if (section === "Basic") {
          return { title: `JS Basic ${idx}`, description: "Sum numbers", starterCode: `console.log(2+3)`, language: "javascript", expectedOutput: "5" };
        }
        if (section === "Practice") {
          return { title: `JS Practice ${idx}`, description: "String upper", starterCode: `console.log("hi".toUpperCase())`, language: "javascript", expectedOutput: "HI" };
        }
        return { title: `JS Project ${idx}`, description: "Array length", starterCode: `console.log([1,2,3].length)`, language: "javascript", expectedOutput: "3" };
      }
    });

    // Java course template
    await createCourseWithContent("java", "Java Basics", "Core Java basics", {
      tasksPerSection: 3,
      taskFactory: (section, idx) => {
        if (section === "Introduction") {
          return { title: `Java Intro ${idx}`, description: "Print Hello", starterCode: `public class Main{public static void main(String[]a){System.out.println("Hello Java");}}`, language: "java", expectedOutput: "Hello Java" };
        }
        if (section === "Basic") {
          return { title: `Java Basic ${idx}`, description: "Print sum", starterCode: `public class Main{public static void main(String[]a){System.out.println(2+3);}}`, language: "java", expectedOutput: "5" };
        }
        if (section === "Practice") {
          return { title: `Java Practice ${idx}`, description: "Print name", starterCode: `public class Main{public static void main(String[]a){System.out.println("Yuva");}}`, language: "java", expectedOutput: "Yuva" };
        }
        return { title: `Java Project ${idx}`, description: "Print array length", starterCode: `public class Main{public static void main(String[]a){int[]x={1,2};System.out.println(x.length);}}`, language: "java", expectedOutput: "2" };
      }
    });

    // Python course template
    await createCourseWithContent("python", "Python Programming", "Beginner → Project Python", {
      tasksPerSection: 3,
      taskFactory: (section, idx) => {
        if (section === "Introduction") {
          return { title: `Python Intro ${idx}`, description: "Print Hello", starterCode: `print("Hello Python")`, language: "python", expectedOutput: "Hello Python" };
        }
        if (section === "Basic") {
          return { title: `Python Basic ${idx}`, description: "Sum numbers", starterCode: `print(2+3)`, language: "python", expectedOutput: "5" };
        }
        if (section === "Practice") {
          return { title: `Python Practice ${idx}`, description: "Uppercase", starterCode: `print("hi".upper())`, language: "python", expectedOutput: "HI" };
        }
        return { title: `Python Project ${idx}`, description: "List length", starterCode: `print(len([1,2,3]))`, language: "python", expectedOutput: "3" };
      }
    });

    console.log("✔ Seeding done.");
  } catch (e) {
    console.error("Seeding error:", e && e.message ? e.message : e);
  }
}

// Call seed on startup (non-blocking)
seedCoursesIfMissing().catch(e => console.error("seedCoursesIfMissing failed:", e));

// ---------- START SERVER ----------
app.listen(PORT, () => console.log(`🔥 Server listening on http://localhost:${PORT}`));
