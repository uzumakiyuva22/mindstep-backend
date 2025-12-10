const router = require('express').Router();
const requireAdmin = (req,res,next)=>{
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token || token !== (process.env.ADMIN_SECRET || 'mindstep_admin_secret')) return res.status(401).json({ success:false, error:'Unauthorized' });
  next();
};

const Course = require('../models/Course');
const Lesson = require('../models/Lesson');
const Task = require('../models/Task');

router.post('/course', requireAdmin, async (req,res)=>{
  try {
    const { slug, title, description } = req.body;
    if (!slug || !title) return res.status(400).json({ success:false, error:'Missing fields' });
    const exists = await Course.findOne({ slug }).lean();
    if (exists) return res.status(409).json({ success:false, error:'Course exists' });
    const c = await Course.create({ slug, title, description });
    res.json({ success:true, course:c });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
});

router.post('/lesson/:courseId', requireAdmin, async (req,res)=>{
  try {
    const courseId = req.params.courseId;
    const { title, section, order, content } = req.body;
    if (!title || !section) return res.status(400).json({ success:false, error:'Missing fields' });
    const l = await Lesson.create({ course_id: courseId, title, section, order: order || 0, content: content || '' });
    res.json({ success:true, lesson:l });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
});

router.post('/task/:lessonId/:courseId', requireAdmin, async (req,res)=>{
  try {
    const { lessonId, courseId } = req.params;
    const { title, description, starterCode, language, expectedOutput } = req.body;
    if (!title) return res.status(400).json({ success:false, error:'Missing title' });
    const t = await Task.create({ lesson_id: lessonId, course_id: courseId, title, description: description || '', starterCode: starterCode || '', language: language || 'python', expectedOutput: expectedOutput || '' });
    res.json({ success:true, task:t });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
});

module.exports = router;
