const { runCodeRemote } = require('../utils/runner');
const Task = require('../models/Task');
const Completion = require('../models/Completion');
const { v4: uuidv4 } = require('uuid');

exports.runTask = async (req,res)=>{
  try {
    const { language, code } = req.body;
    if (!language || typeof code !== 'string') return res.status(400).json({ success:false, error:'Missing fields' });
    if (language === 'html' || language === 'css') return res.json({ success:true, output: code });
    const out = await runCodeRemote(language, code);
    res.json({ success:true, output: out });
  } catch (e){ console.error(e); res.status(500).json({ success:false, error:'Runner error' }); }
};

exports.submitTask = async (req,res)=>{
  try {
    const { userId, taskId, lessonId, courseSlug, output } = req.body;
    if (!userId || !taskId) return res.status(400).json({ success:false, error:'Missing fields' });
    const task = await Task.findById(taskId).lean();
    if (!task) return res.status(404).json({ success:false, error:'Task not found' });

    const expected = String(task.expectedOutput || '').trim();
    let passed = true;
    if (expected.length>0) {
      if (typeof output !== 'string') return res.status(400).json({ success:false, error:'Provide runtime output for checking' });
      passed = String(output||'').trim() === expected;
    }
    if (passed) {
      await Completion.updateOne(
        { user_id:userId, task_id:taskId },
        { $setOnInsert: { _id: uuidv4(), user_id:userId, task_id:taskId, course_id: task.course_id, lesson_id: lessonId || task.lesson_id } },
        { upsert:true }
      );
    }
    res.json({ success:true, passed });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
};

exports.courseProgress = async (req,res)=>{
  try {
    const { slug, userId } = req.params;
    const Course = require('../models/Course');
    const course = await Course.findOne({ slug }).lean();
    if (!course) return res.status(404).json({ success:false, error:'Course not found' });
    const Task = require('../models/Task');
    const totalTasks = await Task.countDocuments({ course_id: course._id });
    const done = await Completion.countDocuments({ user_id: userId, course_id: course._id });
    const percent = totalTasks === 0 ? 0 : Math.round((done / totalTasks)*100);
    res.json({ success:true, courseId: course._id, totalTasks, done, percent });
  } catch(e){ console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
};
