const Course = require('../models/Course');
const Lesson = require('../models/Lesson');
const Task = require('../models/Task');

exports.publicCourses = async (req,res)=>{
  try {
    const courses = await Course.find({}).lean();
    const results = [];
    for (const c of courses) {
      const lessons = await Lesson.find({ course_id:c._id }).lean();
      const totalTasks = await Task.countDocuments({ course_id:c._id });
      results.push({ course:c, lessonCount: lessons.length, totalTasks });
    }
    res.json({ success:true, results });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
};

exports.courseLessons = async (req,res)=>{
  try {
    const slug = req.params.slug;
    const course = await Course.findOne({ slug }).lean();
    if (!course) return res.status(404).json({ success:false, error:'Course not found' });
    const lessons = await Lesson.find({ course_id: course._id }).sort({ order:1 }).lean();
    const tasks = await Task.find({ course_id: course._id }).lean();
    const grouped = lessons.map(l => ({ ...l, tasks: tasks.filter(t => t.lesson_id === l._id) }));
    res.json({ success:true, course, lessons:grouped });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
};

exports.lessonDetails = async (req,res)=>{
  try {
    const lesson = await Lesson.findById(req.params.id).lean();
    if (!lesson) return res.status(404).json({ success:false, error:'Lesson not found' });
    const tasks = await Task.find({ lesson_id: lesson._id }).lean();
    res.json({ success:true, lesson, tasks });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
};
