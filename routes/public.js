const router = require('express').Router();
const ctrl = require('../controllers/public');
router.get('/public/courses', ctrl.publicCourses);
router.get('/course/:slug/lessons', ctrl.courseLessons);
router.get('/lesson/:id/details', ctrl.lessonDetails);
module.exports = router;
